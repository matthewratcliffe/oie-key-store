/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * One name a channel can use, and the secret behind it.
 *
 * <p>The indirection is the point. A channel refers to {@code partnerApiToken}; which
 * vault that comes from, under what name, and which field of it, is configuration that can
 * change without touching a single channel. Moving an interface from a test vault to a
 * production one becomes an edit here rather than a redeploy of everything that used it.
 *
 * <p>{@link #getVariable()} is constrained to letters, digits and underscores starting with
 * a letter, because that is what Velocity will accept after {@code $keystore.} -- a name
 * with a hyphen in it parses as a subtraction and resolves to the literal text, which
 * reaches the far end as a password and fails somewhere much less obvious than here.
 */
public final class SecretBinding {

    /** What Velocity will accept as a property name. */
    private static final Pattern VARIABLE = Pattern.compile("[A-Za-z][A-Za-z0-9_]*");

    private String id = UUID.randomUUID().toString();
    /** The name channels and scripts use. */
    private String variable = "";
    private String connectionId = "";
    /** The secret's name, ARN, path or UUID, depending on the provider. */
    private String secretId = "";
    /**
     * A field to take out of a JSON secret. Empty means the whole payload.
     *
     * <p>Needed most for AWS, whose console writes a key/value secret as one JSON document
     * -- so a database credential is one secret with {@code username} and {@code password}
     * inside it rather than two secrets.
     */
    private String jsonField = "";
    /** A specific version or stage label. Empty means whatever is current. */
    private String version = "";
    private boolean enabled = true;
    /** Free text, for whoever reads the list in a year. */
    private String description = "";

    public String getId() {
        return id;
    }

    public void setId(String id) {
        if (id != null && !id.isBlank()) {
            this.id = id.trim();
        }
    }

    public String getVariable() {
        return variable;
    }

    public void setVariable(String variable) {
        this.variable = variable == null ? "" : variable.strip();
    }

    public String getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(String connectionId) {
        this.connectionId = connectionId == null ? "" : connectionId.strip();
    }

    public String getSecretId() {
        return secretId;
    }

    public void setSecretId(String secretId) {
        this.secretId = secretId == null ? "" : secretId.strip();
    }

    public String getJsonField() {
        return jsonField;
    }

    public void setJsonField(String jsonField) {
        this.jsonField = jsonField == null ? "" : jsonField.strip();
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version == null ? "" : version.strip();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description == null ? "" : description.strip();
    }

    /** How this binding is written in a connector field. */
    public String placeholder(String namespace) {
        return "${" + namespace + "." + variable + "}";
    }

    /** What is missing, in words an administrator can act on. */
    public List<String> problems() {
        List<String> out = new ArrayList<>();
        if (variable.isEmpty()) {
            out.add("Give the binding a variable name.");
        } else if (!VARIABLE.matcher(variable).matches()) {
            out.add("'" + variable + "' cannot be used as a variable name. Use letters, "
                + "digits and underscores, starting with a letter -- anything else will "
                + "not resolve in a connector field.");
        }
        if (connectionId.isEmpty()) {
            out.add("Choose which vault this comes from.");
        }
        if (secretId.isEmpty()) {
            out.add("Name the secret to read.");
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Serialisation
    // ------------------------------------------------------------------

    /** The stored form: percent-encoded {@code name=value} pairs joined by ampersands. */
    public String serialise() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("id", id);
        fields.put("variable", variable);
        fields.put("connectionId", connectionId);
        fields.put("secretId", secretId);
        fields.put("jsonField", jsonField);
        fields.put("version", version);
        fields.put("enabled", Boolean.toString(enabled));
        fields.put("description", description);

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String value = entry.getValue();
            if (value == null || value.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(encode(entry.getKey())).append('=').append(encode(value));
        }
        return sb.toString();
    }

    /** @return the binding, or null when the line carries no id */
    public static SecretBinding parse(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        for (String pair : line.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            fields.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
        }
        if (!fields.containsKey("id")) {
            return null;
        }

        SecretBinding b = new SecretBinding();
        b.setId(fields.get("id"));
        b.setVariable(fields.getOrDefault("variable", ""));
        b.setConnectionId(fields.getOrDefault("connectionId", ""));
        b.setSecretId(fields.getOrDefault("secretId", ""));
        b.setJsonField(fields.getOrDefault("jsonField", ""));
        b.setVersion(fields.getOrDefault("version", ""));
        b.setEnabled(!"false".equalsIgnoreCase(fields.getOrDefault("enabled", "true")));
        b.setDescription(fields.getOrDefault("description", ""));
        return b;
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }
}
