/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import com.fasterxml.jackson.databind.JsonNode;

import org.openintegrationengine.plugins.keystore.VaultConnection;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 1Password through a Connect server.
 *
 * <p>A secret here is not a single value: an item has fields, and which field is wanted
 * has to be said. So the secret id is a path -- {@code vault/item} or
 * {@code vault/item/field} -- and an {@code op://vault/item/field} reference copied out of
 * 1Password may be pasted as it stands, because that is what people have in their hands.
 *
 * <p>Vaults and items may be named or given by UUID. Names are what a human has, so they
 * are resolved by filter and then cached: the lookup is two extra round trips, and a
 * refresh that ran them for every binding every few minutes would be three times the
 * traffic for values that effectively never change.
 */
public final class OnePasswordConnectProvider implements SecretProvider {

    /** Connect item and vault ids: 26 characters of lowercase base32. */
    private static final String UUID_PATTERN = "[a-z0-9]{26}";

    /** Resolved {@code connectionId|kind|name} to id. */
    private final Map<String, String> resolved = new ConcurrentHashMap<>();

    @Override
    public VaultConnection.Type type() {
        return VaultConnection.Type.ONEPASSWORD_CONNECT;
    }

    /** Drops resolved names, so a renamed or recreated item is looked up again. */
    public void forget(String connectionId) {
        resolved.keySet().removeIf(key -> key.startsWith(connectionId + "|"));
    }

    @Override
    public Secret fetch(VaultConnection connection, String secretId, String version)
            throws VaultException {
        Reference reference = Reference.parse(secretId);

        String vaultId = resolveVault(connection, reference.vault);
        String itemId = resolveItem(connection, vaultId, reference.item);

        Http.Result result = call(connection,
            "/v1/vaults/" + vaultId + "/items/" + itemId);
        if (!result.ok()) {
            throw new VaultException(Http.describe("Reading item '" + reference.item + "'",
                result));
        }

        try {
            JsonNode item = Json.parse(result.body);
            String value = pickField(item, reference.field);
            if (value == null) {
                throw new VaultException("Item '" + reference.item + "' has no field "
                    + (reference.field == null ? "holding a password" : "'" + reference.field + "'")
                    + ". It has: " + String.join(", ", fieldLabels(item)) + ".");
            }
            // Connect has no per-version read, and an item's version is not something the
            // API exposes for a field. Reporting the item's revision keeps the "what did
            // we actually get" column honest rather than leaving it blank.
            String revision = Json.string(item, "version");
            return new Secret(value, revision == null ? "" : revision);
        } catch (IOException e) {
            throw new VaultException("Connect returned an item that could not be read.", e);
        }
    }

    /**
     * The field to use.
     *
     * <p>With no field named, the item's password is taken: {@code purpose} is the
     * authoritative marker and a label match is the fallback for items where 1Password has
     * not set one. With a field named, only an exact label or id match counts -- guessing
     * at a near miss would silently hand back the wrong credential.
     */
    private static String pickField(JsonNode item, String wanted) {
        JsonNode fields = item.get("fields");
        if (fields == null || !fields.isArray()) {
            return null;
        }
        if (wanted == null || wanted.isBlank()) {
            for (JsonNode field : fields) {
                if ("PASSWORD".equals(Json.string(field, "purpose"))) {
                    return Json.string(field, "value");
                }
            }
            for (JsonNode field : fields) {
                if ("password".equalsIgnoreCase(String.valueOf(Json.string(field, "label")))) {
                    return Json.string(field, "value");
                }
            }
            return null;
        }
        for (JsonNode field : fields) {
            if (wanted.equalsIgnoreCase(Json.string(field, "label"))
                || wanted.equals(Json.string(field, "id"))) {
                return Json.string(field, "value");
            }
        }
        // A named field matching a purpose, so "username" and "notes" work as written
        // even on items where 1Password does not give those fields a label.
        for (JsonNode field : fields) {
            if (wanted.equalsIgnoreCase(Json.string(field, "purpose"))) {
                return Json.string(field, "value");
            }
        }
        return null;
    }

    private static List<String> fieldLabels(JsonNode item) {
        List<String> out = new ArrayList<>();
        JsonNode fields = item.get("fields");
        if (fields != null && fields.isArray()) {
            for (JsonNode field : fields) {
                String label = Json.string(field, "label");
                if (label == null || label.isBlank()) {
                    label = Json.string(field, "purpose");
                }
                if (label != null && !label.isBlank() && !out.contains(label)) {
                    out.add(label);
                }
            }
        }
        return out.isEmpty() ? List.of("(no named fields)") : out;
    }

    @Override
    public List<String> test(VaultConnection connection) throws VaultException {
        List<String> notes = new ArrayList<>();

        Http.Result result = call(connection, "/v1/vaults");
        if (result.status == 401) {
            throw new VaultException("Connect refused the token. Check that it was issued "
                + "for this Connect server and has not been revoked.");
        }
        if (!result.ok()) {
            throw new VaultException(Http.describe("Listing vaults", result));
        }

        try {
            JsonNode vaults = Json.parse(result.body);
            List<String> names = new ArrayList<>();
            if (vaults.isArray()) {
                for (JsonNode vault : vaults) {
                    String name = Json.string(vault, "name");
                    if (name != null) {
                        names.add(name);
                    }
                }
            }
            if (names.isEmpty()) {
                // A Connect token is granted per vault, so an empty list is a working
                // server with a token nobody finished setting up -- which otherwise shows
                // up much later as "item not found".
                notes.add("Connect is reachable, but this token has access to no vaults. "
                    + "Grant it access in the 1Password integration settings.");
            } else {
                notes.add("Connect is reachable. This token can see: "
                    + String.join(", ", names) + ".");
            }
        } catch (IOException e) {
            throw new VaultException("Connect returned a vault list that could not be read.", e);
        }
        return notes;
    }

    // ------------------------------------------------------------------
    // Name resolution
    // ------------------------------------------------------------------

    private String resolveVault(VaultConnection connection, String vault)
            throws VaultException {
        if (vault.matches(UUID_PATTERN)) {
            return vault;
        }
        String cacheKey = connection.getId() + "|vault|" + vault.toLowerCase(Locale.ROOT);
        String cached = resolved.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        Http.Result result = call(connection, "/v1/vaults?filter=" + filter("name", vault));
        if (!result.ok()) {
            throw new VaultException(Http.describe("Looking up vault '" + vault + "'", result));
        }
        String id = firstId(result.body);
        if (id == null) {
            throw new VaultException("This token can see no vault named '" + vault
                + "'. Check the name, and that the token has been granted access to it.");
        }
        resolved.put(cacheKey, id);
        return id;
    }

    private String resolveItem(VaultConnection connection, String vaultId, String item)
            throws VaultException {
        if (item.matches(UUID_PATTERN)) {
            return item;
        }
        String cacheKey = connection.getId() + "|item|" + vaultId + "|"
            + item.toLowerCase(Locale.ROOT);
        String cached = resolved.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        Http.Result result = call(connection,
            "/v1/vaults/" + vaultId + "/items?filter=" + filter("title", item));
        if (!result.ok()) {
            throw new VaultException(Http.describe("Looking up item '" + item + "'", result));
        }
        String id = firstId(result.body);
        if (id == null) {
            throw new VaultException("That vault has no item titled '" + item + "'.");
        }
        resolved.put(cacheKey, id);
        return id;
    }

    /**
     * A SCIM-style filter, percent-encoded.
     *
     * <p>Double quotes in the value are dropped rather than escaped. The filter grammar
     * has no escape for them, so a title containing one cannot be expressed -- and
     * building a filter that silently ends early is how a lookup matches the wrong item.
     */
    private static String filter(String field, String value) {
        String cleaned = value.replace("\"", "");
        return URLEncoder.encode(field + " eq \"" + cleaned + "\"", StandardCharsets.UTF_8);
    }

    private static String firstId(String body) throws VaultException {
        try {
            JsonNode node = Json.parse(body);
            if (node.isArray() && node.size() > 0) {
                return Json.string(node.get(0), "id");
            }
            return null;
        } catch (IOException e) {
            throw new VaultException("Connect returned a list that could not be read.", e);
        }
    }

    private Http.Result call(VaultConnection connection, String path) throws VaultException {
        try {
            return Http.get(connection.getConnectUrl() + path,
                Map.of("Authorization", "Bearer " + connection.getConnectToken(),
                    "Accept", "application/json"));
        } catch (IOException e) {
            throw new VaultException("Could not reach the Connect server at "
                + connection.getConnectUrl() + ": " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // Secret references
    // ------------------------------------------------------------------

    /** A parsed {@code vault/item[/field]} path. */
    static final class Reference {
        final String vault;
        final String item;
        /** Null means "the item's password". */
        final String field;

        private Reference(String vault, String item, String field) {
            this.vault = vault;
            this.item = item;
            this.field = field;
        }

        static Reference parse(String secretId) throws VaultException {
            String raw = secretId == null ? "" : secretId.strip();
            if (raw.startsWith("op://")) {
                raw = raw.substring("op://".length());
            }
            // A section-qualified reference (vault/item/section/field) is accepted by
            // taking the last segment as the field: Connect's item response is flat, so
            // the section only narrows what a human was looking at, not what is fetched.
            String[] parts = raw.split("/");
            List<String> segments = new ArrayList<>();
            for (String part : parts) {
                if (!part.isBlank()) {
                    segments.add(part.strip());
                }
            }
            if (segments.size() < 2) {
                throw new VaultException("'" + secretId + "' is not a 1Password reference. "
                    + "Use vault/item or vault/item/field.");
            }
            String field = segments.size() > 2 ? segments.get(segments.size() - 1) : null;
            return new Reference(segments.get(0), segments.get(1), field);
        }
    }
}
