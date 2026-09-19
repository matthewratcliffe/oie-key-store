/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import java.util.List;

/**
 * What channel scripts call.
 *
 * <p>From a transformer, deploy script or code template:
 *
 * <pre>
 * var KeyStore = org.openintegrationengine.plugins.keystore.Secrets;
 * var token = KeyStore.get('partnerApiToken');
 * </pre>
 *
 * <p>The values are also in the global map, so {@code globalMap.get('keystore')} reaches
 * the same data and {@code ${keystore.partnerApiToken}} works in any connector field. This
 * class exists because those two are awkward from a script and silent when wrong:
 * {@link #require(String)} in particular fails with the name of the variable that is
 * missing, where a map lookup returns null and the fault surfaces later as an empty
 * password against a remote system.
 *
 * <p>It is also the only one of the three that works everywhere. The global map is cleared
 * by the engine part-way through a "Redeploy All", and although the plugin puts the values
 * straight back, the <em>global</em> deploy script runs in the gap. This class reads what
 * the resolver is holding rather than the global map, so it is unaffected -- which makes
 * it the right choice in a global deploy script specifically.
 *
 * <p>Deliberately static and free of engine types. Everything in it is callable from
 * Rhino without imports, and nothing it returns has to be converted.
 */
public final class Secrets {

    private Secrets() {
    }

    private static SecretResolver resolver() {
        return KeyStoreServicePlugin.resolver();
    }

    /**
     * The value behind a variable.
     *
     * @return the value, or null when there is no such binding or it has no value
     */
    public static String get(String variable) {
        SecretResolver resolver = resolver();
        return resolver == null ? null : resolver.value(variable);
    }

    /** The value behind a variable, or {@code fallback} when it has none. */
    public static String get(String variable, String fallback) {
        String value = get(variable);
        return value == null ? fallback : value;
    }

    /**
     * The value behind a variable, or an exception naming it.
     *
     * <p>The one to use in a deploy script. A channel that cannot get its credential
     * should fail to deploy, loudly, rather than start and authenticate as nobody.
     */
    public static String require(String variable) {
        String value = get(variable);
        if (value == null) {
            throw new IllegalStateException("The key store has no value for '" + variable
                + "'. Check the Key Store page: the binding may be missing, switched off, "
                + "or its last read may have failed.");
        }
        return value;
    }

    /** Whether a variable currently has a value. */
    public static boolean has(String variable) {
        return get(variable) != null;
    }

    /**
     * The variable names that currently have a value.
     *
     * <p>Names only, and no values -- this is for a script that wants to check its
     * prerequisites, not a way to dump the store into a log.
     */
    public static List<String> names() {
        SecretResolver resolver = resolver();
        return resolver == null ? List.of() : resolver.publishedNames();
    }
}
