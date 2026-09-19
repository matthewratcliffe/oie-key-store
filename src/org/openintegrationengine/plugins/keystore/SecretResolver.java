/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.mirth.connect.model.ServerEvent;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.EventController;
import com.mirth.connect.server.util.GlobalVariableStore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openintegrationengine.plugins.keystore.provider.AwsSecretsManagerProvider;
import org.openintegrationengine.plugins.keystore.provider.AzureKeyVaultProvider;
import org.openintegrationengine.plugins.keystore.provider.BitwardenSecretsProvider;
import org.openintegrationengine.plugins.keystore.provider.Json;
import org.openintegrationengine.plugins.keystore.provider.OnePasswordConnectProvider;
import org.openintegrationengine.plugins.keystore.provider.SecretProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reads every binding from its vault and publishes the results where channels can see them.
 *
 * <h2>Where the values go, and why there</h2>
 *
 * <p>Into the engine's global map, under a single key holding a map of name to value, so a
 * connector field written {@code ${keystore.partnerToken}} resolves. That is not a free
 * choice: {@code TemplateValueReplacer.getDefaultContext()} builds its Velocity context
 * from exactly two places, the configuration map and the global map, and everything a
 * connector field can resolve comes from one of them.
 *
 * <p>Of the two, the global map is the only defensible one. The configuration map is
 * persisted to the {@code configuration} table in clear text and is displayed, in full, on
 * a settings page in the Administrator -- putting vault secrets there would mean copying
 * every credential out of the vault and into the database, which is most of the reason for
 * having a vault in the first place. The global map lives in memory, is never written to
 * disk by the engine, and is rebuilt from the vaults on every start.
 *
 * <p>The trade this leaves is real and worth stating: anything that can read the global map
 * can read these values, which includes any JavaScript in any channel on this engine. This
 * plugin narrows who can see a secret down to the engine, not down to a channel. If a
 * channel author must not see a credential, this is not the control that achieves it.
 */
public final class SecretResolver {

    private static final Logger LOG = LogManager.getLogger(SecretResolver.class);

    /** How a binding last turned out. */
    public enum State {
        /** Read from the vault on the last pass. */
        OK,
        /** The last pass failed, but a previously read value is still being served. */
        STALE,
        /** No value is available. The variable is not published at all. */
        FAILED,
        /** Switched off in the binding editor. */
        DISABLED,
        /** The connection it names is switched off, or no longer exists. */
        UNAVAILABLE
    }

    /** What is known about one binding, for the console. Never carries the value. */
    public static final class Status {
        public final String bindingId;
        public final String variable;
        public final String connectionId;
        public final String connectionLabel;
        public final State state;
        /** Empty when there is nothing wrong. */
        public final String detail;
        /** When the value currently held was read, or 0 if there is none. */
        public final long valueAt;
        /** When this binding was last attempted. */
        public final long checkedAt;
        /** The version the vault reported, when it reports one. */
        public final String version;
        /** Length of the resolved value. Enough to spot a truncated paste; not the value. */
        public final int length;

        Status(String bindingId, String variable, String connectionId, String connectionLabel,
               State state, String detail, long valueAt, long checkedAt, String version,
               int length) {
            this.bindingId = bindingId;
            this.variable = variable;
            this.connectionId = connectionId;
            this.connectionLabel = connectionLabel;
            this.state = state;
            this.detail = detail == null ? "" : detail;
            this.valueAt = valueAt;
            this.checkedAt = checkedAt;
            this.version = version == null ? "" : version;
            this.length = length;
        }

        public boolean isFault() {
            return state == State.FAILED || state == State.STALE || state == State.UNAVAILABLE;
        }
    }

    /** The last good value for one binding, and what it was read from. */
    private static final class Held {
        final String value;
        final String version;
        final long readAt;

        Held(String value, String version, long readAt) {
            this.value = value;
            this.version = version;
            this.readAt = readAt;
        }
    }

    private final Map<VaultConnection.Type, SecretProvider> providers =
        new EnumMap<>(VaultConnection.Type.class);

    /** Last known good value per binding id. Memory only; never written anywhere. */
    private final Map<String, Held> held = new ConcurrentHashMap<>();

    /**
     * Exactly what was last put into the global map.
     *
     * <p>Kept so {@link #republish()} can restore it without contacting a vault. The
     * engine clears the whole global map on a redeploy of everything, and the restore runs
     * inside the deploy path -- a network call per binding there would add seconds to
     * every deploy and could fail at the worst moment.
     */
    private volatile Map<String, String> lastPublished = Map.of();

    private volatile List<Status> lastPass = List.of();
    private volatile long lastPassAt;

    public SecretResolver() {
        providers.put(VaultConnection.Type.AZURE_KEY_VAULT, new AzureKeyVaultProvider());
        providers.put(VaultConnection.Type.AWS_SECRETS_MANAGER, new AwsSecretsManagerProvider());
        providers.put(VaultConnection.Type.ONEPASSWORD_CONNECT, new OnePasswordConnectProvider());
        providers.put(VaultConnection.Type.BITWARDEN_SECRETS_MANAGER,
            new BitwardenSecretsProvider());
    }

    public SecretProvider provider(VaultConnection.Type type) {
        return providers.get(type);
    }

    public List<Status> getLastPass() {
        return lastPass;
    }

    public long getLastPassAt() {
        return lastPassAt;
    }

    /**
     * Drops whatever a provider has cached for a connection.
     *
     * <p>Called when a connection is edited or deleted. Without it, a corrected client
     * secret would not be used until the old token expired, which looks exactly like the
     * correction not having been saved.
     */
    public void forget(String connectionId) {
        for (SecretProvider provider : providers.values()) {
            if (provider instanceof AzureKeyVaultProvider) {
                ((AzureKeyVaultProvider) provider).forget(connectionId);
            } else if (provider instanceof AwsSecretsManagerProvider) {
                ((AwsSecretsManagerProvider) provider).forget(connectionId);
            } else if (provider instanceof OnePasswordConnectProvider) {
                ((OnePasswordConnectProvider) provider).forget(connectionId);
            } else if (provider instanceof BitwardenSecretsProvider) {
                ((BitwardenSecretsProvider) provider).forget(connectionId);
            }
        }
    }

    /** Forgets a binding's held value, so a deleted binding stops being published. */
    public void discard(String bindingId) {
        held.remove(bindingId);
    }

    // ------------------------------------------------------------------
    // The refresh pass
    // ------------------------------------------------------------------

    /**
     * Reads every binding and republishes the lot.
     *
     * <p>Every binding is attempted even after one fails. A single unreachable vault must
     * not stop the other three from being refreshed -- and since the published map is
     * rebuilt wholesale from this pass, an early return would also unpublish every secret
     * that was working.
     */
    public synchronized List<Status> refresh() {
        List<SecretBinding> bindings = KeyStoreStore.bindings();
        Map<String, VaultConnection> connections = new LinkedHashMap<>();
        for (VaultConnection connection : KeyStoreStore.connections()) {
            connections.put(connection.getId(), connection);
        }

        boolean staleAllowed = KeyStoreStore.serveStaleOnFailure();
        Map<String, String> published = new LinkedHashMap<>();
        List<Status> statuses = new ArrayList<>();
        long now = System.currentTimeMillis();

        for (SecretBinding binding : bindings) {
            VaultConnection connection = connections.get(binding.getConnectionId());
            String connectionLabel = connection == null ? "" : connection.label();

            if (!binding.isEnabled()) {
                statuses.add(status(binding, connection, State.DISABLED, "", now));
                continue;
            }
            if (connection == null) {
                statuses.add(status(binding, null, State.UNAVAILABLE,
                    "The vault this binding names no longer exists.", now));
                continue;
            }
            if (!connection.isEnabled()) {
                statuses.add(status(binding, connection, State.UNAVAILABLE,
                    "The vault '" + connectionLabel + "' is switched off.", now));
                continue;
            }

            try {
                String value = read(connection, binding);
                held.put(binding.getId(), new Held(value, lastVersion, now));
                published.put(binding.getVariable(), value);
                statuses.add(new Status(binding.getId(), binding.getVariable(),
                    connection.getId(), connectionLabel, State.OK, "", now, now,
                    lastVersion, value.length()));
            } catch (Exception e) {
                Held previous = staleAllowed ? held.get(binding.getId()) : null;
                String detail = describe(e);
                if (previous != null) {
                    published.put(binding.getVariable(), previous.value);
                    statuses.add(new Status(binding.getId(), binding.getVariable(),
                        connection.getId(), connectionLabel, State.STALE,
                        detail + " The value read at " + previous.readAt
                        + " is still being served.",
                        previous.readAt, now, previous.version, previous.value.length()));
                    LOG.warn("key store: could not refresh '{}' from {}; serving the "
                        + "previously read value. {}", binding.getVariable(), connectionLabel,
                        detail);
                } else {
                    held.remove(binding.getId());
                    statuses.add(new Status(binding.getId(), binding.getVariable(),
                        connection.getId(), connectionLabel, State.FAILED, detail,
                        0L, now, "", 0));
                    LOG.error("key store: '{}' could not be read from {}. {}",
                        binding.getVariable(), connectionLabel, detail);
                    audit(binding, connectionLabel, detail);
                }
            }
        }

        publish(published);
        lastPass = List.copyOf(statuses);
        lastPassAt = now;
        return lastPass;
    }

    /**
     * The version reported by the last successful read.
     *
     * <p>Held in a field rather than returned alongside the value because {@link #read}
     * already has two things to say and this one is only ever consumed immediately below
     * it. {@link #refresh()} is synchronized, so there is one writer.
     */
    private String lastVersion = "";

    private String read(VaultConnection connection, SecretBinding binding) throws Exception {
        SecretProvider provider = providers.get(connection.getType());
        if (provider == null) {
            throw new SecretProvider.VaultException("No provider is available for "
                + VaultConnection.describeType(connection.getType()) + ".");
        }

        SecretProvider.Secret secret =
            provider.fetch(connection, binding.getSecretId(), binding.getVersion());
        lastVersion = secret.version;

        String field = binding.getJsonField();
        if (field.isEmpty()) {
            return secret.value;
        }
        String extracted;
        try {
            extracted = Json.field(secret.value, field);
        } catch (IOException e) {
            throw new SecretProvider.VaultException("'" + binding.getSecretId()
                + "' is not a JSON document, so the field '" + field
                + "' cannot be taken out of it.", e);
        }
        if (extracted == null) {
            List<String> names = Json.fieldNames(secret.value);
            throw new SecretProvider.VaultException("'" + binding.getSecretId()
                + "' has no field '" + field + "'."
                + (names.isEmpty() ? " It is not a JSON object."
                    : " It has: " + String.join(", ", names) + "."));
        }
        return extracted;
    }

    private Status status(SecretBinding binding, VaultConnection connection, State state,
                          String detail, long now) {
        Held previous = held.get(binding.getId());
        return new Status(binding.getId(), binding.getVariable(),
            binding.getConnectionId(), connection == null ? "" : connection.label(),
            state, detail, previous == null ? 0L : previous.readAt, now,
            previous == null ? "" : previous.version,
            previous == null ? 0 : previous.value.length());
    }

    /**
     * Unwraps an exception into something worth putting in front of a person.
     *
     * <p>The providers already phrase their own failures. This is for what escapes them:
     * a bare {@code NullPointerException} reaching the console as an empty string is
     * worse than the class name.
     */
    private static String describe(Exception e) {
        String message = e.getMessage();
        if (message != null && !message.isBlank()) {
            return message;
        }
        return e.getClass().getSimpleName() + " while reading the secret.";
    }

    // ------------------------------------------------------------------
    // Publishing
    // ------------------------------------------------------------------

    /**
     * Replaces the published map.
     *
     * <p>One {@code put} of a whole new map rather than mutating the one already there, so
     * a channel resolving a field mid-refresh sees either the previous set or the next
     * one, never a half-updated mixture. The map is unmodifiable so that a script that
     * gets hold of it cannot quietly add a variable of its own.
     *
     * <p>A binding that could not be read is absent rather than present-and-empty. An empty
     * password looks like a configured one and would be sent; a missing key leaves the
     * literal {@code ${keystore.name}} in the field, which fails loudly and says exactly
     * what was not resolved.
     */
    private void publish(Map<String, String> values) {
        Map<String, String> snapshot = Collections.unmodifiableMap(values);
        lastPublished = snapshot;
        try {
            GlobalVariableStore.getInstance().put(KeyStoreStore.namespace(), snapshot);
        } catch (Exception e) {
            LOG.error("key store: could not publish secrets into the global map", e);
        }
    }

    /**
     * Puts the last published set back, if it has gone.
     *
     * <p>This is not belt and braces. Deploying every channel calls
     * {@code clearGlobalMap()} between the undeploy and the deploy -- the engine's own
     * behaviour, controlled by {@code server.resetglobalvariables} and on by default -- so
     * without this every secret vanishes on a "Redeploy All" and does not come back until
     * the next scheduled refresh, which is minutes of channels authenticating with the
     * literal text {@code ${keystore.name}}.
     *
     * <p>Called from the deploy hooks, so it must be cheap and must not throw: no vault is
     * contacted and nothing is read from the database, it simply puts back the map that
     * was already built.
     */
    public void republish() {
        Map<String, String> snapshot = lastPublished;
        if (snapshot.isEmpty()) {
            return;
        }
        try {
            GlobalVariableStore store = GlobalVariableStore.getInstance();
            String namespace = KeyStoreStore.namespace();
            if (store.get(namespace) == snapshot) {
                // Still there, and still the same object. Nothing cleared it.
                return;
            }
            store.put(namespace, snapshot);
            LOG.info("key store: republished {} secret(s) as ${{}.<name>} after the global "
                + "map was cleared", snapshot.size(), namespace);
        } catch (Exception e) {
            LOG.error("key store: could not republish secrets into the global map", e);
        }
    }

    /** Removes the published map entirely, and forgets every held value. On shutdown. */
    public void unpublish() {
        unpublish(KeyStoreStore.namespace());
        held.clear();
        lastPublished = Map.of();
        lastPass = List.of();
    }

    /**
     * Removes one namespace from the global map, without clearing what is held.
     *
     * <p>For a renamed namespace: the values are about to be republished under the new
     * name, and the old key has to go or it would keep resolving with values that nothing
     * refreshes again.
     */
    public void unpublish(String namespace) {
        try {
            GlobalVariableStore.getInstance().remove(namespace);
        } catch (Exception e) {
            LOG.warn("key store: could not remove the published secrets", e);
        }
    }

    /**
     * The value behind a variable, for the script API.
     *
     * @return the value, or null when the variable is unknown or has no value
     */
    public String value(String variable) {
        if (variable == null || variable.isBlank()) {
            return null;
        }
        for (SecretBinding binding : KeyStoreStore.bindings()) {
            if (binding.getVariable().equals(variable.strip())) {
                Held h = held.get(binding.getId());
                return h == null ? null : h.value;
            }
        }
        return null;
    }

    /** The variable names that currently have a value. Names only. */
    public List<String> publishedNames() {
        List<String> out = new ArrayList<>();
        for (Status status : lastPass) {
            if (status.state == State.OK || status.state == State.STALE) {
                out.add(status.variable);
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Audit
    // ------------------------------------------------------------------

    /**
     * Writes a failure into the engine's own event log.
     *
     * <p>Only for a binding with no value at all, not for one being served stale. A stale
     * value is logged and shown in the console but is not an operational event: nothing
     * has stopped working, and an event every refresh interval for a vault that is down
     * for an afternoon would bury the ones that matter.
     */
    private void audit(SecretBinding binding, String connectionLabel, String detail) {
        if (!KeyStoreStore.writeServerEvents()) {
            return;
        }
        try {
            EventController events = ControllerFactory.getFactory().createEventController();

            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("variable", binding.getVariable());
            attributes.put("vault", connectionLabel);
            // The secret's name, never its value. A name in an event log is how someone
            // finds which binding broke; a value in one is a leak that outlives the fault.
            attributes.put("secret", binding.getSecretId());
            attributes.put("reason", detail);

            ServerEvent event = new ServerEvent();
            event.setName("Secret could not be read");
            event.setLevel(ServerEvent.Level.WARNING);
            event.setOutcome(ServerEvent.Outcome.FAILURE);
            event.setAttributes(attributes);
            events.insertEvent(event);
        } catch (Exception e) {
            // Never allowed to escape: failing to record a failure must not become a
            // second failure that stops the rest of the pass. The server log line above
            // has already been written, so nothing is lost.
            LOG.debug("key store: could not write a server event", e);
        }
    }
}
