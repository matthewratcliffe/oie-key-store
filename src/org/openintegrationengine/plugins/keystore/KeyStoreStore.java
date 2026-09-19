/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ControllerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;

/**
 * Persistence for connections, bindings and the plugin's own settings.
 *
 * <p>Written through {@code ConfigurationController.saveProperty}, which puts them in the
 * {@code configuration} table. That matters in this deployment specifically: the image
 * resets {@code conf/} and {@code extensions/} from pristine copies on every boot, so
 * anything written to a file inside the extension directory would not survive a restart.
 *
 * <p>One property per connection and per binding, rather than one property holding all of
 * them. Deleting is then {@code removeProperty} instead of a read-modify-write of a single
 * blob, so two administrators editing different rows at the same time cannot silently drop
 * each other's work.
 *
 * <p>The credential fields inside a connection are encrypted with the engine's own
 * encryptor before the row is written, and decrypted on the way out. The engine's
 * encryptor is keyed from {@code appdata/keystore.jks}, which lives on a different volume
 * from the database in this stack -- so a database dump on its own does not hand over the
 * keys to every vault this engine can read.
 */
public final class KeyStoreStore {

    /** Property group; matches the plugin point name so it groups with the extension. */
    static final String GROUP = "Key Store";

    private static final String CONNECTION_PREFIX = "connection.";
    private static final String BINDING_PREFIX = "binding.";

    private static final String K_NAMESPACE = "namespace";
    private static final String K_REFRESH = "refreshIntervalSeconds";
    private static final String K_STALE_OK = "serveStaleOnFailure";
    private static final String K_AUDIT = "writeServerEvents";

    /**
     * The default namespace. Short, because it is typed into every connector field that
     * uses a secret, and distinct enough not to collide with a global anyone has already.
     */
    static final String DEFAULT_NAMESPACE = "keystore";

    private static final int MIN_REFRESH_SECONDS = 60;
    private static final int DEFAULT_REFRESH_SECONDS = 900;

    private static final Logger LOG = LogManager.getLogger(KeyStoreStore.class);

    private KeyStoreStore() {
    }

    private static ConfigurationController config() {
        return ControllerFactory.getFactory().createConfigurationController();
    }

    private static Properties stored() {
        Properties p = config().getPropertiesForGroup(GROUP);
        return p == null ? new Properties() : p;
    }

    // ------------------------------------------------------------------
    // Connections
    // ------------------------------------------------------------------

    /** Every connection, with credentials decrypted, ordered by name. */
    public static List<VaultConnection> connections() {
        Properties p = stored();
        List<VaultConnection> out = new ArrayList<>();
        for (String key : p.stringPropertyNames()) {
            if (!key.startsWith(CONNECTION_PREFIX)) {
                continue;
            }
            VaultConnection c = VaultConnection.parse(p.getProperty(key));
            if (c == null) {
                // Dropped rather than fatal: one unreadable row must not take out every
                // other vault this engine reads from.
                LOG.warn("key store: ignoring unreadable connection '{}'", key);
                continue;
            }
            decryptInto(c);
            out.add(c);
        }
        out.sort(Comparator.comparing(VaultConnection::label, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(VaultConnection::getId));
        return out;
    }

    public static VaultConnection connection(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        VaultConnection c = VaultConnection.parse(
            stored().getProperty(CONNECTION_PREFIX + id.trim()));
        if (c != null) {
            decryptInto(c);
        }
        return c;
    }

    public static void saveConnection(VaultConnection connection) {
        VaultConnection copy = VaultConnection.parse(connection.serialise());
        encryptInto(copy);
        config().saveProperty(GROUP, CONNECTION_PREFIX + connection.getId(), copy.serialise());
    }

    public static void deleteConnection(String id) {
        if (id != null && !id.isBlank()) {
            config().removeProperty(GROUP, CONNECTION_PREFIX + id.trim());
        }
    }

    /**
     * Encrypts the credential fields in place.
     *
     * <p>Field by field rather than encrypting the whole row, so the non-secret half of a
     * connection stays legible in the database. Diagnosing "which vault is this pointing
     * at" should not require the engine's keystore.
     */
    private static void encryptInto(VaultConnection c) {
        ConfigurationController config = config();
        c.setClientSecret(encrypt(config, c.getClientSecret()));
        c.setSecretAccessKey(encrypt(config, c.getSecretAccessKey()));
        c.setSessionToken(encrypt(config, c.getSessionToken()));
        c.setConnectToken(encrypt(config, c.getConnectToken()));
        c.setAccessToken(encrypt(config, c.getAccessToken()));
    }

    private static void decryptInto(VaultConnection c) {
        ConfigurationController config = config();
        c.setClientSecret(decrypt(config, c.getClientSecret()));
        c.setSecretAccessKey(decrypt(config, c.getSecretAccessKey()));
        c.setSessionToken(decrypt(config, c.getSessionToken()));
        c.setConnectToken(decrypt(config, c.getConnectToken()));
        c.setAccessToken(decrypt(config, c.getAccessToken()));
    }

    private static String encrypt(ConfigurationController config, String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return config.getEncryptor().encrypt(value);
    }

    private static String decrypt(ConfigurationController config, String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        try {
            return config.getEncryptor().decrypt(value);
        } catch (Exception e) {
            // A credential that cannot be decrypted is treated as absent rather than
            // fatal: the keystore may have been replaced, and the operator needs the page
            // to load so they can re-enter it.
            LOG.warn("key store: a stored credential could not be decrypted; "
                + "it will need to be entered again");
            return "";
        }
    }

    // ------------------------------------------------------------------
    // Bindings
    // ------------------------------------------------------------------

    /** Every binding, ordered by variable name so the list is stable. */
    public static List<SecretBinding> bindings() {
        Properties p = stored();
        List<SecretBinding> out = new ArrayList<>();
        for (String key : p.stringPropertyNames()) {
            if (!key.startsWith(BINDING_PREFIX)) {
                continue;
            }
            SecretBinding b = SecretBinding.parse(p.getProperty(key));
            if (b == null) {
                LOG.warn("key store: ignoring unreadable binding '{}'", key);
                continue;
            }
            out.add(b);
        }
        out.sort(Comparator.comparing(SecretBinding::getVariable, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(SecretBinding::getId));
        return out;
    }

    public static SecretBinding binding(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        return SecretBinding.parse(stored().getProperty(BINDING_PREFIX + id.trim()));
    }

    public static void saveBinding(SecretBinding binding) {
        config().saveProperty(GROUP, BINDING_PREFIX + binding.getId(), binding.serialise());
    }

    public static void deleteBinding(String id) {
        if (id != null && !id.isBlank()) {
            config().removeProperty(GROUP, BINDING_PREFIX + id.trim());
        }
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    /**
     * The global map key the secrets are published under.
     *
     * <p>Sanitised on the way out, not only on the way in: a namespace that is not a valid
     * Velocity identifier would make every binding silently unresolvable, and a value
     * written directly into the configuration table by hand should not be able to do that.
     */
    public static String namespace() {
        String value = stored().getProperty(K_NAMESPACE, DEFAULT_NAMESPACE);
        return value != null && value.matches("[A-Za-z][A-Za-z0-9_]*")
            ? value : DEFAULT_NAMESPACE;
    }

    public static void setNamespace(String namespace) {
        String value = namespace == null ? "" : namespace.strip();
        config().saveProperty(GROUP, K_NAMESPACE,
            value.matches("[A-Za-z][A-Za-z0-9_]*") ? value : DEFAULT_NAMESPACE);
    }

    /** How often every binding is re-read. Floored at a minute; these are network calls. */
    public static int refreshIntervalSeconds() {
        return Math.max(MIN_REFRESH_SECONDS,
            parseInt(stored().getProperty(K_REFRESH), DEFAULT_REFRESH_SECONDS));
    }

    public static void setRefreshIntervalSeconds(int seconds) {
        config().saveProperty(GROUP, K_REFRESH,
            Integer.toString(Math.max(MIN_REFRESH_SECONDS, seconds)));
    }

    /**
     * Whether a value that fails to refresh keeps its last known good value.
     *
     * <p>On by default, and the default is the whole argument for this plugin over putting
     * credentials in the configuration map: a vault being briefly unreachable should not
     * stop channels that are already running, because the credential has not changed --
     * only our ability to re-read it has. Turn it off where a revoked secret must stop
     * being usable within the refresh interval, and accept the outage that implies.
     */
    public static boolean serveStaleOnFailure() {
        return !"false".equalsIgnoreCase(stored().getProperty(K_STALE_OK, "true"));
    }

    public static void setServeStaleOnFailure(boolean serveStale) {
        config().saveProperty(GROUP, K_STALE_OK, Boolean.toString(serveStale));
    }

    /** Whether refresh failures also write a WARNING into the engine's own event log. */
    public static boolean writeServerEvents() {
        return !"false".equalsIgnoreCase(stored().getProperty(K_AUDIT, "true"));
    }

    public static void setWriteServerEvents(boolean write) {
        config().saveProperty(GROUP, K_AUDIT, Boolean.toString(write));
    }

    static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.strip());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
