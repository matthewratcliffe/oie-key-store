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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bitwarden Secrets Manager.
 *
 * <p>The odd one of the four. Azure, AWS and 1Password all return a secret's value in
 * plain text over TLS; Bitwarden is zero-knowledge, so the API returns ciphertext and the
 * organisation key needed to read it arrives encrypted under a key derived from the access
 * token. {@link BitwardenCrypto} does that work; this class is the session around it.
 *
 * <p>A session is an access token plus the organisation key, held for as long as the
 * identity endpoint said the token is good for. Both are re-derived together: they come
 * from the same response, and keeping a stale organisation key beside a fresh access token
 * would decrypt to rubbish rather than fail.
 */
public final class BitwardenSecretsProvider implements SecretProvider {

    /** Bitwarden's own name for the derivation the access token key goes through. */
    private static final String KEY_NAME = "accesstoken";
    private static final String KEY_INFO = "sm-access-token";

    /** A UUID, which is how Secrets Manager identifies a secret. */
    private static final String UUID_PATTERN =
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    /** Resolved {@code connectionId|key} to secret id. */
    private final Map<String, String> resolved = new ConcurrentHashMap<>();

    private static final class Session {
        final String accessToken;
        final BitwardenCrypto.SymmetricKey organisationKey;
        final String organisationId;
        final long expiresAt;

        Session(String accessToken, BitwardenCrypto.SymmetricKey organisationKey,
                String organisationId, long expiresAt) {
            this.accessToken = accessToken;
            this.organisationKey = organisationKey;
            this.organisationId = organisationId;
            this.expiresAt = expiresAt;
        }

        boolean isUsable() {
            return System.currentTimeMillis() < expiresAt - 60_000L;
        }
    }

    @Override
    public VaultConnection.Type type() {
        return VaultConnection.Type.BITWARDEN_SECRETS_MANAGER;
    }

    /** Drops the session and any resolved names, so an edited token takes effect at once. */
    public void forget(String connectionId) {
        sessions.remove(connectionId);
        resolved.keySet().removeIf(key -> key.startsWith(connectionId + "|"));
    }

    @Override
    public Secret fetch(VaultConnection connection, String secretId, String version)
            throws VaultException {
        String wanted = secretId == null ? "" : secretId.strip();
        if (wanted.isEmpty()) {
            throw new VaultException("No secret key or UUID was given.");
        }
        if (version != null && !version.isBlank()) {
            // Said plainly rather than ignored. A binding that names a version and is
            // quietly given the current value is the kind of thing found during an
            // incident, not before one.
            throw new VaultException("Bitwarden Secrets Manager does not expose secret "
                + "versions, so the version field must be left empty.");
        }

        Session session = session(connection);
        String id = wanted.matches(UUID_PATTERN)
            ? wanted : resolveByKey(connection, session, wanted);

        Http.Result result = call(connection, session, "/secrets/" + id);
        if (result.status == 404) {
            throw new VaultException("Bitwarden has no secret with id " + id
                + ", or this machine account cannot see it.");
        }
        if (!result.ok()) {
            throw new VaultException(Http.describe("Reading secret '" + wanted + "'", result));
        }

        try {
            JsonNode node = Json.parse(result.body);
            String encrypted = Json.string(node, "value");
            if (encrypted == null) {
                throw new VaultException("Bitwarden returned no value for '" + wanted + "'.");
            }
            String value = BitwardenCrypto.decrypt(encrypted, session.organisationKey);
            // The revision date stands in for a version: it is the only thing Bitwarden
            // reports that changes when the value does.
            String revision = Json.string(node, "revisionDate");
            return new Secret(value, revision == null ? "" : revision);
        } catch (IOException e) {
            throw new VaultException("Bitwarden returned a secret that could not be read.", e);
        }
    }

    @Override
    public List<String> test(VaultConnection connection) throws VaultException {
        List<String> notes = new ArrayList<>();
        Session session = session(connection);
        notes.add("Authenticated to organisation " + session.organisationId
            + " and decrypted the organisation key.");

        List<String[]> secrets = list(connection, session);
        if (secrets.isEmpty()) {
            notes.add("The machine account can see no secrets. Give it read access to a "
                + "project in the Secrets Manager machine account settings.");
        } else {
            List<String> names = new ArrayList<>();
            for (int i = 0; i < Math.min(8, secrets.size()); i++) {
                names.add(secrets.get(i)[1]);
            }
            notes.add("It can see " + secrets.size() + " secret(s), including: "
                + String.join(", ", names) + ".");
        }
        return notes;
    }

    // ------------------------------------------------------------------
    // Secrets by key
    // ------------------------------------------------------------------

    /**
     * Finds a secret by its key.
     *
     * <p>Costs a list and a decryption of every key in it, because the keys are ciphertext
     * and the server therefore cannot filter on them. The result is cached: this is the
     * expensive path and a key does not usually change identity.
     */
    private String resolveByKey(VaultConnection connection, Session session, String key)
            throws VaultException {
        String cacheKey = connection.getId() + "|" + key.toLowerCase(Locale.ROOT);
        String cached = resolved.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        List<String[]> secrets = list(connection, session);
        List<String> matches = new ArrayList<>();
        String found = null;
        for (String[] secret : secrets) {
            if (key.equals(secret[1])) {
                matches.add(secret[0]);
                found = secret[0];
            }
        }
        if (found == null) {
            throw new VaultException("This machine account can see no secret with the key '"
                + key + "'. Check the key, and that the account has access to its project.");
        }
        if (matches.size() > 1) {
            // Bitwarden allows the same key in two projects. Picking one silently would
            // make which credential a channel gets depend on list order.
            throw new VaultException("More than one secret has the key '" + key
                + "'. Bind it by UUID instead so there is no ambiguity.");
        }
        resolved.put(cacheKey, found);
        return found;
    }

    /** Every visible secret, as {@code {id, decrypted key}} pairs. */
    private List<String[]> list(VaultConnection connection, Session session)
            throws VaultException {
        Http.Result result = call(connection, session,
            "/organizations/" + URLEncoder.encode(session.organisationId,
                StandardCharsets.UTF_8) + "/secrets");
        if (!result.ok()) {
            throw new VaultException(Http.describe("Listing secrets", result));
        }

        List<String[]> out = new ArrayList<>();
        try {
            JsonNode body = Json.parse(result.body);
            // The list has been served under more than one envelope across versions, so
            // all three shapes are accepted rather than pinning to whichever one this
            // server happens to use.
            JsonNode items = body.isArray() ? body
                : body.has("data") ? body.get("data")
                : body.get("secrets");
            if (items == null || !items.isArray()) {
                return out;
            }
            for (JsonNode item : items) {
                String id = Json.string(item, "id");
                String encryptedKey = Json.string(item, "key");
                if (id == null || encryptedKey == null) {
                    continue;
                }
                try {
                    out.add(new String[] {id, BitwardenCrypto.decrypt(encryptedKey,
                        session.organisationKey)});
                } catch (VaultException e) {
                    // One undecryptable name must not hide every other secret. It is
                    // listed by id so it is at least visible, and bindable that way.
                    out.add(new String[] {id, "(unreadable name, id " + id + ")"});
                }
            }
        } catch (IOException e) {
            throw new VaultException("Bitwarden returned a list that could not be read.", e);
        }
        return out;
    }

    private Http.Result call(VaultConnection connection, Session session, String path)
            throws VaultException {
        try {
            return Http.get(connection.getApiUrl() + path,
                Map.of("Authorization", "Bearer " + session.accessToken,
                    "Accept", "application/json"));
        } catch (IOException e) {
            throw new VaultException("Could not reach the Bitwarden API at "
                + connection.getApiUrl() + ": " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    private Session session(VaultConnection connection) throws VaultException {
        Session cached = sessions.get(connection.getId());
        if (cached != null && cached.isUsable()) {
            return cached;
        }
        Session fresh = authenticate(connection);
        sessions.put(connection.getId(), fresh);
        return fresh;
    }

    private Session authenticate(VaultConnection connection) throws VaultException {
        AccessToken token = AccessToken.parse(connection.getAccessToken());

        String body = form(Map.of(
            "grant_type", "client_credentials",
            "scope", "api.secrets",
            "client_id", token.clientId,
            "client_secret", token.clientSecret));

        Http.Result result;
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Accept", "application/json");
            // The identity server records which kind of client authenticated; the SDK
            // reports 21, and sending nothing has been known to be rejected outright.
            headers.put("Device-Type", "21");
            result = Http.post(connection.getIdentityUrl() + "/connect/token", headers, body);
        } catch (IOException e) {
            throw new VaultException("Could not reach the Bitwarden identity server at "
                + connection.getIdentityUrl() + ": " + e.getMessage(), e);
        }
        if (result.status == 400 || result.status == 401) {
            throw new VaultException("Bitwarden refused the access token. Check that it has "
                + "not been revoked or expired, and that it was issued for this server.");
        }
        if (!result.ok()) {
            throw new VaultException(Http.describe("Authenticating with Bitwarden", result));
        }

        try {
            JsonNode node = Json.parse(result.body);
            String accessToken = Json.string(node, "access_token");
            String encryptedPayload = Json.string(node, "encrypted_payload");
            if (accessToken == null || encryptedPayload == null) {
                throw new VaultException("Bitwarden's token response was missing the access "
                    + "token or the encrypted payload.");
            }

            BitwardenCrypto.SymmetricKey tokenKey = BitwardenCrypto.deriveShareableKey(
                token.encryptionKey, KEY_NAME, KEY_INFO);
            String payload = BitwardenCrypto.decrypt(encryptedPayload, tokenKey);
            String organisationKeyBase64 = Json.string(Json.parse(payload), "encryptionKey");
            if (organisationKeyBase64 == null) {
                throw new VaultException("Bitwarden's encrypted payload carried no "
                    + "organisation key.");
            }
            BitwardenCrypto.SymmetricKey organisationKey = BitwardenCrypto.keyFromBytes(
                Base64.getDecoder().decode(organisationKeyBase64));

            String organisationId = connection.getOrganizationId().isEmpty()
                ? organisationFromJwt(accessToken) : connection.getOrganizationId();
            if (organisationId == null || organisationId.isEmpty()) {
                throw new VaultException("Could not tell which organisation this token "
                    + "belongs to. Set the organisation ID on the connection.");
            }

            String expiresIn = Json.string(node, "expires_in");
            long expiresAt = System.currentTimeMillis()
                + (expiresIn != null && expiresIn.matches("\\d+")
                    ? Long.parseLong(expiresIn) * 1000L : 1_800_000L);

            return new Session(accessToken, organisationKey, organisationId, expiresAt);
        } catch (IOException e) {
            throw new VaultException("Bitwarden's token response could not be read.", e);
        } catch (IllegalArgumentException e) {
            throw new VaultException("Bitwarden's organisation key was not valid base64.", e);
        }
    }

    /**
     * The {@code organization} claim of the returned JWT.
     *
     * <p>Read, not verified. This token was just received over TLS from the identity
     * server the connection names, and the claim is only used to build the URL of the next
     * request to that same server -- a forged one would fail there rather than grant
     * anything. Verifying the signature would mean fetching and pinning Bitwarden's
     * signing keys for no gain.
     */
    private static String organisationFromJwt(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return null;
        }
        try {
            String claims = new String(Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8);
            return Json.string(Json.parse(claims), "organization");
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    /** The three parts of {@code 0.<client id>.<client secret>:<encryption key>}. */
    static final class AccessToken {
        final String clientId;
        final String clientSecret;
        final byte[] encryptionKey;

        private AccessToken(String clientId, String clientSecret, byte[] encryptionKey) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.encryptionKey = encryptionKey;
        }

        static AccessToken parse(String raw) throws VaultException {
            String token = raw == null ? "" : raw.strip();
            int colon = token.indexOf(':');
            if (colon < 0) {
                throw new VaultException("The access token is missing its encryption key. "
                    + "A complete token has a colon and a base64 key after it.");
            }
            String[] parts = token.substring(0, colon).split("\\.");
            if (parts.length != 3 || !"0".equals(parts[0])) {
                throw new VaultException("The access token is not in the expected format "
                    + "(0.<id>.<secret>:<key>).");
            }
            byte[] key;
            try {
                // Bitwarden omits the padding, which the strict decoder rejects.
                key = Base64.getDecoder().decode(pad(token.substring(colon + 1)));
            } catch (IllegalArgumentException e) {
                throw new VaultException("The access token's encryption key is not valid "
                    + "base64.", e);
            }
            if (key.length != 16) {
                throw new VaultException("The access token's encryption key is "
                    + key.length + " bytes; 16 were expected.");
            }
            return new AccessToken(parts[1], parts[2], key);
        }

        private static String pad(String base64) {
            int remainder = base64.length() % 4;
            return remainder == 0 ? base64 : base64 + "====".substring(remainder);
        }
    }

    private static String form(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
              .append(URLEncoder.encode(e.getValue() == null ? "" : e.getValue(),
                  StandardCharsets.UTF_8));
        }
        return sb.toString();
    }
}
