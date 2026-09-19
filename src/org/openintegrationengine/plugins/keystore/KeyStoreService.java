/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openintegrationengine.plugins.keystore.provider.SecretProvider;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the servlet calls. Turns connections, bindings and the last refresh into shapes the
 * console can read.
 *
 * <p>Every list returned to the browser is a list of tab-separated strings rather than a
 * list of objects, and every list is a plain {@link ArrayList}. Both are the scars of the
 * same problem, already paid for by the volume monitor in this repository: the engine
 * serialises API responses with XStream, whose rendering of an immutable list is
 * undecodable and whose rendering of a list of maps the console's decoder cannot reliably
 * unpick. A flat list of strings survives the round trip, and the browser splits on the tab.
 *
 * <p><b>No method here returns a secret value, and none returns a stored credential.</b>
 * The console shows what a binding is called, where it comes from, whether it resolved and
 * how long the value is -- never the value. A credential field arrives from the browser
 * and never goes back to it, which is also what lets a blank field mean "leave the stored
 * one alone" when a connection is edited.
 */
public final class KeyStoreService {

    private static final Logger LOG = LogManager.getLogger(KeyStoreService.class);

    private final SecretResolver resolver;

    public KeyStoreService(SecretResolver resolver) {
        this.resolver = resolver;
    }

    public SecretResolver resolver() {
        return resolver;
    }

    /**
     * Strips the field separator out of a value.
     *
     * <p>Names and descriptions come from users and could contain a tab; a single stray tab
     * would otherwise shift every later field by one and silently corrupt the row.
     */
    private static String flat(String s) {
        return s == null ? "" : s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    // ------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------

    /**
     * The state of every binding.
     *
     * @param refresh true to read from the vaults now; false to report the last pass
     */
    public Map<String, Object> status(boolean refresh) {
        List<SecretResolver.Status> results = refresh
            ? resolver.refresh()
            : resolver.getLastPass();

        // Never refreshed yet -- the server has only just started. Reading once here is
        // better than an empty page that looks like "nothing is configured".
        if (!refresh && results.isEmpty() && resolver.getLastPassAt() == 0
            && !KeyStoreStore.bindings().isEmpty()) {
            results = resolver.refresh();
        }

        String namespace = KeyStoreStore.namespace();
        int faults = 0;
        List<String> rows = new ArrayList<>();
        for (SecretResolver.Status s : results) {
            if (s.isFault()) {
                faults++;
            }
            rows.add(String.join("\t",
                flat(s.bindingId),
                flat(s.variable),
                flat(s.connectionId),
                flat(s.connectionLabel),
                s.state.name(),
                flat(s.detail),
                Long.toString(s.valueAt),
                Long.toString(s.checkedAt),
                flat(s.version),
                Integer.toString(s.length),
                "${" + namespace + "." + flat(s.variable) + "}"));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("faults", faults);
        out.put("bindingCount", results.size());
        out.put("connectionCount", KeyStoreStore.connections().size());
        out.put("lastPassAt", resolver.getLastPassAt());
        out.put("namespace", namespace);
        out.put("refreshIntervalSeconds", KeyStoreStore.refreshIntervalSeconds());
        out.put("serveStaleOnFailure", KeyStoreStore.serveStaleOnFailure());
        out.put("writeServerEvents", KeyStoreStore.writeServerEvents());
        out.put("results", rows);
        return out;
    }

    /** Just the fault count, for the navigation badge. Cheap: reads no vault. */
    public Map<String, Object> summary() {
        int faults = 0;
        for (SecretResolver.Status s : resolver.getLastPass()) {
            if (s.isFault()) {
                faults++;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("faults", faults);
        out.put("bindingCount", KeyStoreStore.bindings().size());
        out.put("lastPassAt", resolver.getLastPassAt());
        return out;
    }

    /** Reads every binding from its vault now. */
    public Map<String, Object> refresh() {
        List<SecretResolver.Status> results = resolver.refresh();
        int faults = 0;
        for (SecretResolver.Status s : results) {
            if (s.isFault()) {
                faults++;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("refreshed", results.size());
        out.put("faults", faults);
        return out;
    }

    // ------------------------------------------------------------------
    // Connections
    // ------------------------------------------------------------------

    public Map<String, Object> connections() {
        List<String> rows = new ArrayList<>();
        for (VaultConnection c : KeyStoreStore.connections()) {
            rows.add(serialiseForUi(c));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("connections", rows);
        return out;
    }

    /**
     * One connection as the console sees it.
     *
     * <p>{@code hasCredential} rather than the credential: the editor needs to know
     * whether one is stored so it can say "leave blank to keep the existing one" instead of
     * presenting an empty field that looks like nothing was ever entered.
     */
    private String serialiseForUi(VaultConnection c) {
        return String.join("\t",
            flat(c.getId()),
            flat(c.getName()),
            c.getType().name(),
            c.getAuthMode().name(),
            Boolean.toString(c.isEnabled()),
            flat(c.getVaultUrl()),
            flat(c.getTenantId()),
            flat(c.getClientId()),
            flat(c.getApiVersion()),
            flat(c.getRegion()),
            flat(c.getAccessKeyId()),
            flat(c.getRoleArn()),
            flat(c.getEndpointOverride()),
            flat(c.getConnectUrl()),
            flat(c.getIdentityUrl()),
            flat(c.getApiUrl()),
            flat(c.getOrganizationId()),
            Boolean.toString(hasStoredCredential(c)),
            flat(c.label()));
    }

    private static boolean hasStoredCredential(VaultConnection c) {
        switch (c.getType()) {
            case AZURE_KEY_VAULT:
                return !c.getClientSecret().isEmpty();
            case AWS_SECRETS_MANAGER:
                return !c.getSecretAccessKey().isEmpty();
            case ONEPASSWORD_CONNECT:
                return !c.getConnectToken().isEmpty();
            case BITWARDEN_SECRETS_MANAGER:
                return !c.getAccessToken().isEmpty();
            default:
                return false;
        }
    }

    /**
     * Creates a connection, or updates the one named by {@code id}.
     *
     * <p>Rejects rather than saving-and-warning. A half-filled vault connection is not a
     * work in progress that can be come back to: it sits in the list looking configured,
     * and every binding pointing at it fails at the moment a channel needs a credential.
     */
    public Map<String, Object> saveConnection(Map<String, String> incoming) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, String> fields = incoming == null ? Map.of() : incoming;

        String id = fields.get("id");
        boolean isNew = id == null || id.isBlank();
        VaultConnection connection = isNew ? new VaultConnection() : KeyStoreStore.connection(id);
        if (connection == null) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "That connection no longer exists; it may have been deleted.");
            return out;
        }

        applyTo(connection, fields);

        List<String> problems = new ArrayList<>(connection.problems());
        // A warning is not a refusal. The one warning that exists -- a plain-http Connect
        // server -- describes a deployment people really do run, and refusing it would
        // make the plugin unusable for them rather than informed.
        problems.removeIf(problem -> problem.startsWith("Warning:"));
        if (!problems.isEmpty()) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "This connection is not complete.");
            out.put("problems", problems);
            return out;
        }

        KeyStoreStore.saveConnection(connection);
        // Any cached token or session belonged to the previous settings. Dropping it means
        // a corrected credential is used on the next call rather than whenever the old
        // token happened to expire -- which otherwise looks like the fix not having saved.
        resolver.forget(connection.getId());

        LOG.info("key store connection '{}' saved: {} via {}", connection.label(),
            VaultConnection.describeType(connection.getType()),
            VaultConnection.describeAuthMode(connection.getAuthMode()));

        out.put("ok", Boolean.TRUE);
        out.put("id", connection.getId());
        out.put("saved", Boolean.TRUE);
        return out;
    }

    /**
     * Applies a submitted form onto a connection.
     *
     * <p>An absent key leaves the field alone, and for the credential fields an empty
     * string does too. That is what makes "leave blank to keep the existing secret" work:
     * the console is never sent a credential, so it has nothing to send back, and a
     * cleared field would otherwise wipe a working one every time the name was edited.
     * Clearing is a separate, explicit {@code clearCredential} flag.
     */
    private void applyTo(VaultConnection connection, Map<String, String> fields) {
        if (fields.containsKey("name")) {
            connection.setName(fields.get("name"));
        }
        if (fields.containsKey("type")) {
            connection.setType(VaultConnection.parseEnum(VaultConnection.Type.class,
                fields.get("type"), connection.getType()));
        }
        if (fields.containsKey("authMode")) {
            connection.setAuthMode(VaultConnection.parseEnum(VaultConnection.AuthMode.class,
                fields.get("authMode"), connection.getAuthMode()));
        }
        if (fields.containsKey("enabled")) {
            connection.setEnabled(Boolean.parseBoolean(fields.get("enabled")));
        }
        if (fields.containsKey("vaultUrl")) {
            connection.setVaultUrl(fields.get("vaultUrl"));
        }
        if (fields.containsKey("tenantId")) {
            connection.setTenantId(fields.get("tenantId"));
        }
        if (fields.containsKey("clientId")) {
            connection.setClientId(fields.get("clientId"));
        }
        if (fields.containsKey("apiVersion")) {
            connection.setApiVersion(fields.get("apiVersion"));
        }
        if (fields.containsKey("region")) {
            connection.setRegion(fields.get("region"));
        }
        if (fields.containsKey("accessKeyId")) {
            connection.setAccessKeyId(fields.get("accessKeyId"));
        }
        if (fields.containsKey("roleArn")) {
            connection.setRoleArn(fields.get("roleArn"));
        }
        if (fields.containsKey("endpointOverride")) {
            connection.setEndpointOverride(fields.get("endpointOverride"));
        }
        if (fields.containsKey("connectUrl")) {
            connection.setConnectUrl(fields.get("connectUrl"));
        }
        if (fields.containsKey("identityUrl")) {
            connection.setIdentityUrl(fields.get("identityUrl"));
        }
        if (fields.containsKey("apiUrl")) {
            connection.setApiUrl(fields.get("apiUrl"));
        }
        if (fields.containsKey("organizationId")) {
            connection.setOrganizationId(fields.get("organizationId"));
        }

        if (Boolean.parseBoolean(fields.get("clearCredential"))) {
            connection.setClientSecret("");
            connection.setSecretAccessKey("");
            connection.setSessionToken("");
            connection.setConnectToken("");
            connection.setAccessToken("");
        }
        setIfSupplied(fields, "clientSecret", connection::setClientSecret);
        setIfSupplied(fields, "secretAccessKey", connection::setSecretAccessKey);
        setIfSupplied(fields, "sessionToken", connection::setSessionToken);
        setIfSupplied(fields, "connectToken", connection::setConnectToken);
        setIfSupplied(fields, "accessToken", connection::setAccessToken);
    }

    private static void setIfSupplied(Map<String, String> fields, String key,
                                      java.util.function.Consumer<String> setter) {
        String value = fields.get(key);
        if (value != null && !value.isEmpty()) {
            setter.accept(value);
        }
    }

    public Map<String, Object> deleteConnection(String id) {
        Map<String, Object> out = new LinkedHashMap<>();
        VaultConnection existing = KeyStoreStore.connection(id);
        if (existing == null) {
            // Idempotent: a delete of something already gone is the state the caller asked
            // for, and reporting it as an error only makes a double-click look broken.
            out.put("ok", Boolean.TRUE);
            out.put("deleted", Boolean.FALSE);
            return out;
        }

        // Bindings are not deleted with it. A connection removed by mistake is then one
        // edit away from being restored, whereas cascading the delete would take every
        // binding that used it and there is no undo for that.
        List<String> orphaned = new ArrayList<>();
        for (SecretBinding binding : KeyStoreStore.bindings()) {
            if (binding.getConnectionId().equals(existing.getId())) {
                orphaned.add(binding.getVariable());
            }
        }

        KeyStoreStore.deleteConnection(id);
        resolver.forget(existing.getId());
        resolver.refresh();

        LOG.info("key store connection '{}' deleted", existing.label());

        out.put("ok", Boolean.TRUE);
        out.put("deleted", Boolean.TRUE);
        if (!orphaned.isEmpty()) {
            out.put("warning", orphaned.size() + " binding(s) referred to that vault and no "
                + "longer resolve: " + String.join(", ", orphaned));
        }
        return out;
    }

    /**
     * Proves a connection works, before anything depends on it.
     *
     * <p>Takes the whole form rather than an id, so an unsaved connection can be tested --
     * which is the moment it is most worth testing. When an id is supplied and a credential
     * field is left blank, the stored credential is used, so testing an existing connection
     * does not mean retyping the secret.
     */
    public Map<String, Object> testConnection(Map<String, String> incoming) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, String> fields = incoming == null ? Map.of() : incoming;

        String id = fields.get("id");
        VaultConnection connection = (id == null || id.isBlank())
            ? new VaultConnection() : KeyStoreStore.connection(id);
        if (connection == null) {
            connection = new VaultConnection();
        }
        applyTo(connection, fields);

        List<String> problems = new ArrayList<>(connection.problems());
        problems.removeIf(problem -> problem.startsWith("Warning:"));
        if (!problems.isEmpty()) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "This connection is not complete.");
            out.put("problems", problems);
            return out;
        }

        SecretProvider provider = resolver.provider(connection.getType());
        if (provider == null) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "No provider is available for "
                + VaultConnection.describeType(connection.getType()) + ".");
            return out;
        }

        try {
            List<String> notes = new ArrayList<>(provider.test(connection));
            out.put("ok", Boolean.TRUE);
            out.put("notes", notes);
        } catch (Exception e) {
            String message = e.getMessage();
            out.put("ok", Boolean.FALSE);
            out.put("error", message == null || message.isBlank()
                ? e.getClass().getSimpleName() : message);
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Bindings
    // ------------------------------------------------------------------

    public Map<String, Object> bindings() {
        Map<String, String> labels = new LinkedHashMap<>();
        for (VaultConnection c : KeyStoreStore.connections()) {
            labels.put(c.getId(), c.label());
        }

        String namespace = KeyStoreStore.namespace();
        List<String> rows = new ArrayList<>();
        for (SecretBinding b : KeyStoreStore.bindings()) {
            rows.add(String.join("\t",
                flat(b.getId()),
                flat(b.getVariable()),
                flat(b.getConnectionId()),
                flat(labels.getOrDefault(b.getConnectionId(), "")),
                flat(b.getSecretId()),
                flat(b.getJsonField()),
                flat(b.getVersion()),
                Boolean.toString(b.isEnabled()),
                flat(b.getDescription()),
                flat(b.placeholder(namespace))));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("namespace", namespace);
        out.put("bindings", rows);
        return out;
    }

    public Map<String, Object> saveBinding(Map<String, String> incoming) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, String> fields = incoming == null ? Map.of() : incoming;

        String id = fields.get("id");
        boolean isNew = id == null || id.isBlank();
        SecretBinding binding = isNew ? new SecretBinding() : KeyStoreStore.binding(id);
        if (binding == null) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "That binding no longer exists; it may have been deleted.");
            return out;
        }

        if (fields.containsKey("variable")) {
            binding.setVariable(fields.get("variable"));
        }
        if (fields.containsKey("connectionId")) {
            binding.setConnectionId(fields.get("connectionId"));
        }
        if (fields.containsKey("secretId")) {
            binding.setSecretId(fields.get("secretId"));
        }
        if (fields.containsKey("jsonField")) {
            binding.setJsonField(fields.get("jsonField"));
        }
        if (fields.containsKey("version")) {
            binding.setVersion(fields.get("version"));
        }
        if (fields.containsKey("enabled")) {
            binding.setEnabled(Boolean.parseBoolean(fields.get("enabled")));
        }
        if (fields.containsKey("description")) {
            binding.setDescription(fields.get("description"));
        }

        List<String> problems = new ArrayList<>(binding.problems());

        // Two bindings under one name would mean the value a channel gets depends on which
        // was written to the map last, which is to say on load order. Caught here because
        // the published map has no way to represent the conflict.
        for (SecretBinding existing : KeyStoreStore.bindings()) {
            if (!existing.getId().equals(binding.getId())
                && existing.getVariable().equals(binding.getVariable())) {
                problems.add("Another binding already uses the variable name '"
                    + binding.getVariable() + "'.");
                break;
            }
        }
        if (!binding.getConnectionId().isEmpty()
            && KeyStoreStore.connection(binding.getConnectionId()) == null) {
            problems.add("The vault this binding names no longer exists.");
        }

        if (!problems.isEmpty()) {
            out.put("ok", Boolean.FALSE);
            out.put("error", "This binding is not complete.");
            out.put("problems", problems);
            return out;
        }

        KeyStoreStore.saveBinding(binding);
        LOG.info("key store binding '{}' saved: {} from connection {}",
            binding.getVariable(), binding.getSecretId(), binding.getConnectionId());

        // Refreshed at once so the list shows whether the new binding actually resolves,
        // rather than nothing until the next scheduled pass -- which may be a quarter of
        // an hour away, and by then whoever saved it has moved on.
        resolver.refresh();

        out.put("ok", Boolean.TRUE);
        out.put("id", binding.getId());
        out.put("saved", Boolean.TRUE);
        return out;
    }

    public Map<String, Object> deleteBinding(String id) {
        Map<String, Object> out = new LinkedHashMap<>();
        SecretBinding existing = KeyStoreStore.binding(id);
        if (existing == null) {
            out.put("ok", Boolean.TRUE);
            out.put("deleted", Boolean.FALSE);
            return out;
        }
        KeyStoreStore.deleteBinding(id);
        // Dropped from memory as well as from storage, so the value stops being published
        // on this pass rather than lingering until the engine restarts.
        resolver.discard(existing.getId());
        resolver.refresh();

        LOG.info("key store binding '{}' deleted", existing.getVariable());

        out.put("ok", Boolean.TRUE);
        out.put("deleted", Boolean.TRUE);
        return out;
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    public Map<String, Object> saveSettings(Map<String, String> incoming) {
        Map<String, String> fields = incoming == null ? Map.of() : incoming;

        String previousNamespace = KeyStoreStore.namespace();
        if (fields.containsKey("namespace")) {
            KeyStoreStore.setNamespace(fields.get("namespace"));
        }
        if (fields.containsKey("refreshIntervalSeconds")) {
            KeyStoreStore.setRefreshIntervalSeconds(
                KeyStoreStore.parseInt(fields.get("refreshIntervalSeconds"), 900));
        }
        if (fields.containsKey("serveStaleOnFailure")) {
            KeyStoreStore.setServeStaleOnFailure(
                Boolean.parseBoolean(fields.get("serveStaleOnFailure")));
        }
        if (fields.containsKey("writeServerEvents")) {
            KeyStoreStore.setWriteServerEvents(
                Boolean.parseBoolean(fields.get("writeServerEvents")));
        }

        String namespace = KeyStoreStore.namespace();
        List<String> notes = new ArrayList<>();
        if (!namespace.equals(previousNamespace)) {
            // The old key is still in the global map holding the previous values, and
            // would go on resolving for channels that still reference it -- quietly, and
            // without ever being refreshed again. Removing it makes those channels fail
            // visibly, which is the only way anyone finds out they were missed.
            resolver.unpublish(previousNamespace);
            notes.add("Every connector field and script must now use ${" + namespace
                + ".name}. Anything still written ${" + previousNamespace
                + ".name} has stopped resolving.");
        }
        resolver.refresh();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("namespace", namespace);
        out.put("refreshIntervalSeconds", KeyStoreStore.refreshIntervalSeconds());
        out.put("serveStaleOnFailure", KeyStoreStore.serveStaleOnFailure());
        out.put("writeServerEvents", KeyStoreStore.writeServerEvents());
        // The scheduler reads its period once when it starts, so a changed interval only
        // takes effect on restart. Said plainly rather than left for someone to discover.
        notes.add("A changed refresh interval takes effect when the server restarts.");
        out.put("notes", notes);
        return out;
    }
}
