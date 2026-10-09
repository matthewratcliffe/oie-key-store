/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openintegrationengine.plugins.keystore.provider.SecretProvider;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Any secret in one vault, by its name, with no binding in between.
 *
 * <p>Published into the global map under the vault's reference name, so a connector field
 * can say {@code ${AWS['au-prod/htrak_postgres'].password}}. The bracket form is not a
 * style choice: the engine's Velocity parses {@code ${AWS.au-prod/htrak_postgres.password}}
 * as a syntax error -- a hyphen or a slash cannot appear in a property name -- and on a
 * syntax error the engine leaves the <em>whole</em> field unreplaced, not just that
 * reference.
 *
 * <p>Read on first use and cached. A connector resolves its fields on every message, so
 * the cache is what keeps that from being a call to the vault per message; after the first
 * read, the refresh pass re-reads every name that has been asked for, on the same schedule
 * as the bindings, so rotation behaves the same way for both.
 *
 * <p>A lookup-only map: {@link #entrySet()} is empty, so iterating or printing it -- which
 * a script logging {@code globalMap} would do -- shows nothing. Only a name already known
 * to the caller gets a value.
 */
public final class DirectReferences extends AbstractMap<String, Object> {

    private static final Logger LOG = LogManager.getLogger(DirectReferences.class);

    /**
     * How long a failed first read is remembered before the next lookup tries again.
     *
     * <p>Without it, a misspelt name in a connector field would cost a vault call on every
     * message, which is how a typo turns into rate limiting for every other channel.
     */
    static final long RETRY_AFTER_MS = 60_000L;

    /**
     * A name nobody has looked up for this long stops being refreshed.
     *
     * <p>Long enough that a daily batch keeps its entry; short enough that a channel that
     * has been deleted stops costing a vault call per pass.
     */
    static final long FORGET_AFTER_MS = 24L * 60 * 60 * 1000;

    /**
     * Names that are never looked up: this class's own method names.
     *
     * <p>Rhino reads {@code refs.get} on a Java map as the map key {@code "get"} first and
     * only falls back to the method when that comes back null. Without this, every script
     * that called {@code globalMap.get('AWS').get(...)} would ask the vault for a secret
     * called "get", and list it on the console as a secret that cannot be read.
     */
    private static final Set<String> METHOD_NAMES = methodNames();

    private static Set<String> methodNames() {
        Set<String> out = new HashSet<>();
        for (Method method : DirectReferences.class.getMethods()) {
            out.add(method.getName());
        }
        return Set.copyOf(out);
    }

    /** What is known about one name. Replaced whole, never mutated, except for use time. */
    private static final class Entry {
        final SecretValue value;
        final String version;
        final long readAt;
        final String error;
        final long checkedAt;
        volatile long usedAt;

        Entry(SecretValue value, String version, long readAt, String error, long checkedAt,
              long usedAt) {
            this.value = value;
            this.version = version == null ? "" : version;
            this.readAt = readAt;
            this.error = error == null ? "" : error;
            this.checkedAt = checkedAt;
            this.usedAt = usedAt;
        }
    }

    /** One name's state, for the console. Never carries the value. */
    public static final class Status {
        public final String prefix;
        public final String secretId;
        public final SecretResolver.State state;
        public final String detail;
        public final long valueAt;
        public final long checkedAt;
        public final String version;
        public final int length;

        Status(String prefix, String secretId, SecretResolver.State state, String detail,
               long valueAt, long checkedAt, String version, int length) {
            this.prefix = prefix;
            this.secretId = secretId;
            this.state = state;
            this.detail = detail;
            this.valueAt = valueAt;
            this.checkedAt = checkedAt;
            this.version = version;
            this.length = length;
        }

        public boolean isFault() {
            return state != SecretResolver.State.OK;
        }
    }

    private final String prefix;
    private final SecretProvider provider;
    private volatile VaultConnection connection;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    DirectReferences(VaultConnection connection, SecretProvider provider) {
        this.prefix = connection.getReferencePrefix();
        this.provider = provider;
        this.connection = connection;
    }

    /** The global map key this is published under. */
    String prefix() {
        return prefix;
    }

    String connectionId() {
        return connection.getId();
    }

    /** Takes up an edited connection, so a changed credential is used on the next read. */
    void use(VaultConnection updated) {
        this.connection = updated;
    }

    /**
     * The secret behind a name, or null when it cannot be read.
     *
     * <p>Null leaves the literal {@code ${...}} in the connector field, which is the same
     * failure a binding without a value gives, for the same reason: an empty string looks
     * like a configured password and would be sent.
     */
    @Override
    public SecretValue get(Object key) {
        String secretId = key == null ? "" : key.toString().strip();
        if (secretId.isEmpty() || METHOD_NAMES.contains(secretId)) {
            return null;
        }
        long now = System.currentTimeMillis();
        Entry entry = entries.get(secretId);
        if (entry == null || (entry.value == null && now - entry.checkedAt >= RETRY_AFTER_MS)) {
            // Two threads asking for the same new name at once may both read it. That is
            // one extra call, once, and cheaper than holding a lock across a network call
            // that every other lookup would then queue behind.
            entry = read(secretId, entry, false, now);
        }
        entry.usedAt = now;
        return entry.value;
    }

    @Override
    public boolean containsKey(Object key) {
        return get(key) != null;
    }

    /** Empty, deliberately: see the class comment. */
    @Override
    public Set<Map.Entry<String, Object>> entrySet() {
        return Collections.emptySet();
    }

    /**
     * Re-reads every name that has been asked for, and forgets the ones nobody has.
     *
     * <p>Called from the refresh pass, never from a message thread.
     */
    void refresh(boolean staleAllowed) {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Entry> e : entries.entrySet()) {
            if (now - e.getValue().usedAt > FORGET_AFTER_MS) {
                entries.remove(e.getKey(), e.getValue());
                continue;
            }
            read(e.getKey(), e.getValue(), staleAllowed, now);
        }
    }

    private Entry read(String secretId, Entry previous, boolean staleAllowed, long now) {
        long usedAt = previous == null ? now : previous.usedAt;
        Entry next;
        try {
            SecretProvider.Secret secret = provider.fetch(connection, secretId, "");
            next = new Entry(new SecretValue(secret.value), secret.version, now, "", now, usedAt);
        } catch (Exception e) {
            String detail = SecretResolver.describe(e);
            if (staleAllowed && previous != null && previous.value != null) {
                next = new Entry(previous.value, previous.version, previous.readAt,
                    detail + " The value read at " + previous.readAt
                    + " is still being served.", now, usedAt);
                LOG.warn("key store: could not refresh ${}['{}']; serving the previously "
                    + "read value. {}", prefix, secretId, detail);
            } else {
                next = new Entry(null, "", 0L, detail, now, usedAt);
                LOG.error("key store: ${}['{}'] could not be read from {}. {}", prefix,
                    secretId, connection.label(), detail);
            }
        }
        entries.put(secretId, next);
        return next;
    }

    /** Every name that has been asked for, in name order. */
    List<Status> statuses() {
        List<Status> out = new ArrayList<>();
        for (Map.Entry<String, Entry> e : entries.entrySet()) {
            Entry entry = e.getValue();
            SecretResolver.State state = entry.value == null ? SecretResolver.State.FAILED
                : entry.error.isEmpty() ? SecretResolver.State.OK : SecretResolver.State.STALE;
            out.add(new Status(prefix, e.getKey(), state, entry.error, entry.readAt,
                entry.checkedAt, entry.version,
                entry.value == null ? 0 : entry.value.raw().length()));
        }
        out.sort((a, b) -> a.secretId.compareToIgnoreCase(b.secretId));
        return out;
    }

    /**
     * Identity, not content. AbstractMap's equality would make every two of these equal --
     * both have no entries -- and the resolver tells them apart with {@code ==} anyway.
     */
    @Override
    public boolean equals(Object other) {
        return this == other;
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }
}
