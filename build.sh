#!/usr/bin/env bash
#
# Builds the Key Store engine extension into dist/keystore-<version>.zip.
#
#   ./plugins/oie-key-store/build.sh
#
# No local JDK or Maven required: it compiles inside a container and takes the
# engine jars straight out of the image this repo builds, so it is always
# compiled against exactly the engine it will run on. That matters because the
# jars are not published to Maven Central -- the usual alternative is a
# third-party mirror pinned to some other version.
#
# Like the volume monitor and unlike the git sync extension, this one bundles
# nothing. All four vaults are reached over their documented HTTPS APIs using
# the JDK's own HttpClient, and the only library it needs beyond the engine's
# controllers is Jackson, which the engine already loads from server-lib. So
# there are no third-party jars to verify and nothing extra in the engine's JVM.
#
# Environment:
#   OIE_IMAGE      image to take engine jars from   (default oie/engine:4.6.0)
#   JDK_IMAGE      compiler image                   (default eclipse-temurin:21-jdk)
#   PLUGIN_VERSION version stamped into plugin.xml   (default 0.1.0)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${HERE}"

OIE_IMAGE="${OIE_IMAGE:-oie/engine:4.6.0}"
JDK_IMAGE="${JDK_IMAGE:-eclipse-temurin:21-jdk}"
PLUGIN_VERSION="${PLUGIN_VERSION:-0.1.0}"

# Must match the engine the extension is installed on, or ExtensionLoader
# refuses it outright -- compatibility is an exact string match.
MIRTH_VERSION="${MIRTH_VERSION:-4.6.0}"

BUILD="${HERE}/build"
LIBS="${BUILD}/libs"
DIST="${HERE}/dist"

log() { printf '==> %s\n' "$*"; }

########################################################################
# 1. Engine jars, straight from the image
########################################################################
prepare_libs() {
    mkdir -p "$LIBS"

    if [[ -f "${LIBS}/.engine-jars-ok" ]]; then
        log "engine jars already extracted (rm -rf ${BUILD} to refresh)"
        return 0
    fi

    log "extracting engine jars from ${OIE_IMAGE}"
    # A throwaway container is the only way to read an image's filesystem
    # without a running one; `docker create` does not start it.
    local cid
    cid="$(docker create "$OIE_IMAGE" /bin/true)"
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' RETURN

    local jar
    for jar in \
        server-lib/mirth-server.jar \
        server-lib/mirth-client-core.jar \
        server-lib/mirth-crypto.jar \
        server-lib/xstream-1.4.20.jar \
        client-lib/donkey-model.jar \
        client-lib/log4j-api-2.25.3.jar \
        client-lib/javax.ws.rs-api-2.0.1.jar \
        client-lib/swagger-annotations-2.0.10.jar \
        client-lib/jersey-media-multipart-2.22.1.jar
    do
        docker cp "${cid}:/opt/engine/${jar}" "${LIBS}/$(basename "$jar")" >/dev/null
    done
    docker cp "${cid}:/opt/engine/server-lib/donkey/donkey-server.jar" "${LIBS}/" >/dev/null

    # javax.servlet-api is needed for the servlet's HttpServletRequest, and lives
    # under the web server's own lib directory rather than server-lib.
    docker cp "${cid}:/opt/engine/server-lib/javax/javax.servlet-api-3.1.0.jar" "${LIBS}/" >/dev/null

    # mirth-crypto carries the Encryptor the stored credentials go through, and
    # xstream is needed only so javac can read the annotations on the engine's
    # own model classes -- without it every reference to ServerEvent warns, and
    # -Werror below turns that into a failed build.
    #
    # Jackson, for reading the vaults' JSON. All of these are compile-time only -- the engine
    # already has these on the classpath that extensions are loaded beneath, so
    # they are deliberately NOT packaged into the zip. Bundling a second copy
    # would put two Jacksons in one JVM for no gain.
    local jackson
    for jackson in jackson-core-2.14.3.jar jackson-databind-2.14.3.jar \
                   jackson-annotations-2.14.3.jar
    do
        docker cp "${cid}:/opt/engine/server-lib/jackson/${jackson}" "${LIBS}/" >/dev/null
    done

    touch "${LIBS}/.engine-jars-ok"
    log "extracted $(ls -1 "${LIBS}"/*.jar | wc -l) engine jars"
}

########################################################################
# 2. Compile
########################################################################
compile() {
    log "compiling with ${JDK_IMAGE}"
    rm -rf "${BUILD}/classes"
    mkdir -p "${BUILD}/classes"

    # Paths are passed relative to the mount so this works the same on Windows.
    #
    # -Xlint:all with -Werror: this plugin handles credentials, and an unchecked
    # cast or a fallthrough in that code is worth stopping the build for.
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "${HERE}:/p" \
        -w /p \
        "$JDK_IMAGE" \
        sh -c '
            set -e
            CP=$(ls build/libs/*.jar 2>/dev/null | tr "\n" ":")
            find src -name "*.java" > build/sources.txt
            echo "    $(wc -l < build/sources.txt) source files"
            javac -Xlint:all -Xlint:-options -Werror -source 17 -target 17 \
                -cp "$CP" -d build/classes @build/sources.txt
        '
    log "compiled"
}

########################################################################
# 3. Verify the Bitwarden key derivation
########################################################################
#
# Bitwarden Secrets Manager is zero-knowledge: values arrive encrypted and are
# decrypted here. A derivation that is subtly wrong does not fail -- it produces
# a different key, which fails the MAC check at best and yields rubbish at
# worst. Bitwarden publishes test vectors for it, so the build checks against
# them rather than finding out in production.
selftest() {
    log "checking Bitwarden key derivation against published vectors"
    MSYS_NO_PATHCONV=1 docker run --rm -v "${HERE}:/p" -w /p "$JDK_IMAGE" sh -c '
        cat > /tmp/SelfTest.java <<EOF
import org.openintegrationengine.plugins.keystore.provider.BitwardenCrypto;
public class SelfTest {
    public static void main(String[] a) {
        String r = BitwardenCrypto.selfTest();
        if (r != null) { System.err.println("    FAILED: " + r); System.exit(1); }
        System.out.println("    derive_shareable_key matches both published vectors");
    }
}
EOF
        javac -cp build/classes -d /tmp /tmp/SelfTest.java
        java -cp build/classes:/tmp SelfTest
    '
}

########################################################################
# 4. Package
########################################################################
package() {
    local stage="${BUILD}/stage/keystore"
    rm -rf "${BUILD}/stage"
    mkdir -p "${stage}/libs" "${DIST}"

    # One jar for the whole extension. The engine's extension classloader does
    # not care about the client/server/shared split unless the Swing client
    # needs its own half, and this plugin's UI is the web console.
    MSYS_NO_PATHCONV=1 docker run --rm -v "${HERE}:/p" -w /p "$JDK_IMAGE" \
        sh -c 'cd build/classes && jar cf ../stage/keystore/libs/keystore-server.jar .'

    # plugin.xml carries the version and the compatibility string, both of which
    # have to be right or the extension is silently not loaded.
    sed -e "s|@PLUGIN_VERSION@|${PLUGIN_VERSION}|g" \
        -e "s|@MIRTH_VERSION@|${MIRTH_VERSION}|g" \
        "${HERE}/plugin.xml.in" > "${stage}/plugin.xml"

    # The console UI half travels inside the extension, so one install delivers
    # both (the pattern documented in the web administrator's PLUGINS.md).
    cp -a "${HERE}/webadmin" "${stage}/webadmin"

    local zip="${DIST}/keystore-${PLUGIN_VERSION}.zip"
    rm -f "$zip"
    MSYS_NO_PATHCONV=1 docker run --rm -v "${HERE}:/p" -w /p "$JDK_IMAGE" \
        sh -c "cd build/stage && jar cfM ../../dist/keystore-${PLUGIN_VERSION}.zip keystore"

    log "built ${zip#"$ROOT/"}"
    sha256sum "$zip" | sed 's/^/    /'
}

prepare_libs
compile
selftest
package

cat <<EOF

Install it by dropping the zip in extensions/ and restarting:

    cp $(printf '%s' "${DIST}/keystore-${PLUGIN_VERSION}.zip" | sed "s|${ROOT}/||") extensions/
    docker compose up -d --force-recreate engine
    ./scripts/oie-check-extensions.sh "Key Store"
EOF
