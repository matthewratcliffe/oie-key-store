/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The little JSON this plugin needs.
 *
 * <p>Jackson is taken from the engine's own {@code server-lib/jackson} rather than bundled:
 * the launcher puts the whole of {@code server-lib} on the classpath that extensions are
 * loaded beneath, which is the same route by which the git sync extension uses XStream
 * without shipping it.
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    public static JsonNode parse(String text) throws IOException {
        return MAPPER.readTree(text == null ? "" : text);
    }

    /** A top-level string field, or null if absent or not a string. */
    public static String string(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() || !value.isValueNode() ? null : value.asText();
    }

    /**
     * Whether a secret's payload is a JSON object, and so can have a field picked out of it.
     *
     * <p>Worth asking, because Secrets Manager's own console writes key/value secrets as a
     * JSON object while a "plaintext" secret is whatever the user typed -- and what they
     * typed is quite often a bare password that happens to start with a digit, which is
     * valid JSON but not an object.
     */
    public static boolean isObject(String text) {
        if (text == null) {
            return false;
        }
        String trimmed = text.strip();
        if (!trimmed.startsWith("{")) {
            return false;
        }
        try {
            return parse(trimmed).isObject();
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Pulls one field out of a JSON secret payload.
     *
     * @return the field's value, or null when the payload is not an object or has no
     *         such field -- the caller reports that as a binding error, because silently
     *         handing back the whole JSON document as a password is far worse
     */
    public static String field(String text, String name) throws IOException {
        JsonNode root = parse(text);
        if (!root.isObject()) {
            return null;
        }
        JsonNode value = root.get(name);
        if (value == null || value.isNull()) {
            return null;
        }
        // asText() on an object or array gives "", which would look like an empty
        // password. Anything non-scalar is re-serialised so the value is at least honest.
        return value.isValueNode() ? value.asText() : value.toString();
    }

    /** The field names of a JSON object payload, for the binding editor's hint. */
    public static List<String> fieldNames(String text) {
        List<String> out = new ArrayList<>();
        try {
            JsonNode root = parse(text);
            if (root.isObject()) {
                for (Iterator<String> it = root.fieldNames(); it.hasNext(); ) {
                    out.add(it.next());
                }
            }
        } catch (IOException e) {
            // A payload that will not parse simply has no field names to offer.
        }
        return out;
    }

    /** Escapes a string for embedding in a JSON document literal. */
    public static String quote(String value) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    // Control characters have to be escaped or the document is invalid
                    // JSON; everything else, including non-ASCII, is legal as it stands.
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.append('"').toString();
    }
}
