/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import com.fasterxml.jackson.databind.JsonNode;

import org.openintegrationengine.plugins.keystore.provider.Json;

import java.io.IOException;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * One secret read through a direct reference, shaped so a connector field can take it
 * apart.
 *
 * <p>A map of the secret's JSON fields, so {@code ${AWS['prod/db'].password}} resolves the
 * field, and a {@link #toString()} of the whole payload, so {@code ${AWS['prod/token']}}
 * resolves a plain-text secret. Velocity renders a reference with {@code toString()} and
 * looks up {@code .name} on a map with {@code get("name")}, which is all this has to be.
 *
 * <p>No public {@code getX()} or {@code isX()} methods, on purpose. Velocity tries a getter
 * before it tries the map, so a {@code getVersion()} here would quietly shadow a secret
 * field called {@code version}.
 */
public final class SecretValue extends AbstractMap<String, String> {

    private final String raw;
    private final Map<String, String> fields;

    public SecretValue(String raw) {
        this.raw = raw == null ? "" : raw;
        this.fields = Collections.unmodifiableMap(fieldsOf(this.raw));
    }

    /**
     * The fields of a JSON object payload, each as the text a connector field should get.
     *
     * <p>Empty for anything that is not an object, including a plain password that happens
     * to parse as a JSON number -- see {@link Json#isObject}.
     */
    private static Map<String, String> fieldsOf(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (!Json.isObject(raw)) {
            return out;
        }
        try {
            JsonNode root = Json.parse(raw);
            for (Iterator<Map.Entry<String, JsonNode>> it = root.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> field = it.next();
                JsonNode value = field.getValue();
                if (value == null || value.isNull()) {
                    // Absent rather than "null": a missing field leaves the literal
                    // ${...} in place, which fails loudly, where the text "null" would
                    // be sent as a password.
                    continue;
                }
                // Same rule as Json.field: a nested object is re-serialised rather than
                // turned into the empty string that asText() would give.
                out.put(field.getKey(), value.isValueNode() ? value.asText() : value.toString());
            }
        } catch (IOException e) {
            // isObject said it parses; if it does not after all, there are no fields.
        }
        return out;
    }

    /** The payload exactly as the vault returned it. */
    public String raw() {
        return raw;
    }

    @Override
    public String get(Object key) {
        return key == null ? null : fields.get(key.toString());
    }

    @Override
    public boolean containsKey(Object key) {
        return key != null && fields.containsKey(key.toString());
    }

    @Override
    public Set<Map.Entry<String, String>> entrySet() {
        return fields.entrySet();
    }

    /** The whole payload, which is what {@code ${AWS['name']}} renders. */
    @Override
    public String toString() {
        return raw;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SecretValue && ((SecretValue) other).raw.equals(raw);
    }

    @Override
    public int hashCode() {
        return raw.hashCode();
    }
}
