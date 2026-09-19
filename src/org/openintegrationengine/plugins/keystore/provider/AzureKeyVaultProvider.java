/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import com.fasterxml.jackson.databind.JsonNode;

import org.openintegrationengine.plugins.keystore.VaultConnection;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Azure Key Vault over its data-plane REST API.
 *
 * <p>The vault itself is one GET. Everything else here is acquiring the bearer token to
 * make it with, which is where the four ways of running on Azure differ: an app
 * registration's client secret, the identity the platform injects into App Service and
 * Container Apps, the IMDS endpoint on a virtual machine, and the projected token AKS
 * writes into the pod for workload identity.
 */
public final class AzureKeyVaultProvider implements SecretProvider {

    /** The resource every Key Vault data-plane call is scoped to, public cloud included. */
    private static final String SCOPE = "https://vault.azure.net/.default";
    /** IMDS wants the bare resource rather than a scope. */
    private static final String RESOURCE = "https://vault.azure.net";

    private static final String IMDS_TOKEN_URL =
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01";

    /**
     * Tokens live about an hour and are the expensive half of a fetch, so they are cached
     * per connection. Keyed by connection id and not by the connection object: the console
     * hands out a fresh instance on every load, and an identity-keyed cache would never
     * hit.
     */
    private final Map<String, CachedToken> tokens = new ConcurrentHashMap<>();

    private static final class CachedToken {
        final String value;
        final long expiresAt;

        CachedToken(String value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }

        /** A minute of slack, so a token cannot expire in flight. */
        boolean isUsable() {
            return System.currentTimeMillis() < expiresAt - 60_000L;
        }
    }

    @Override
    public VaultConnection.Type type() {
        return VaultConnection.Type.AZURE_KEY_VAULT;
    }

    /** Drops a cached token, so an edited credential takes effect at once. */
    public void forget(String connectionId) {
        tokens.remove(connectionId);
    }

    @Override
    public Secret fetch(VaultConnection connection, String secretId, String version)
            throws VaultException {
        String name = secretId == null ? "" : secretId.strip();
        if (name.isEmpty()) {
            throw new VaultException("No secret name was given.");
        }
        // A secret name may not contain a slash, so a value that has one is a path from
        // somewhere else -- most often an "op://" style reference pasted by habit. Saying
        // so beats a 404 from Azure that names a secret nobody meant to ask for.
        if (name.contains("/")) {
            throw new VaultException("'" + name + "' is not a Key Vault secret name. "
                + "Use just the name, and put the version in the version field.");
        }

        String url = connection.getVaultUrl() + "/secrets/"
            + URLEncoder.encode(name, StandardCharsets.UTF_8);
        if (version != null && !version.isBlank()) {
            url += "/" + URLEncoder.encode(version.strip(), StandardCharsets.UTF_8);
        }
        url += "?api-version=" + connection.getApiVersion();

        Http.Result result = call(url, token(connection));
        if (result.status == 404) {
            throw new VaultException("Key Vault has no secret named '" + name + "'"
                + (version == null || version.isBlank() ? "" : " at version " + version) + ".");
        }
        if (result.status == 403) {
            throw new VaultException("Key Vault refused access to '" + name + "'. The "
                + "identity needs the Get permission on secrets, through an access policy "
                + "or the Key Vault Secrets User role.");
        }
        if (!result.ok()) {
            throw new VaultException(Http.describe("Reading '" + name + "'", result));
        }

        try {
            JsonNode body = Json.parse(result.body);
            String value = Json.string(body, "value");
            if (value == null) {
                // Key Vault answers 200 with no value for a secret whose current version is
                // disabled, which is otherwise indistinguishable from an empty password.
                throw new VaultException("Key Vault returned no value for '" + name
                    + "'. The version may be disabled.");
            }
            return new Secret(value, versionFromId(Json.string(body, "id")));
        } catch (IOException e) {
            throw new VaultException("Key Vault returned a response that could not be read.", e);
        }
    }

    /** The trailing segment of {@code .../secrets/NAME/VERSION}. */
    private static String versionFromId(String id) {
        if (id == null) {
            return "";
        }
        int slash = id.lastIndexOf('/');
        return slash < 0 ? "" : id.substring(slash + 1);
    }

    @Override
    public List<String> test(VaultConnection connection) throws VaultException {
        List<String> notes = new ArrayList<>();

        String token = token(connection);
        notes.add("Acquired a token for " + connection.getVaultUrl()
            + " using " + VaultConnection.describeAuthMode(connection.getAuthMode()) + ".");

        // Listing is a separate permission from getting, and an identity that can read the
        // one secret it was granted will be refused here. That is a working setup, so a
        // 403 on the list is reported as information rather than failing the test.
        String url = connection.getVaultUrl() + "/secrets?maxresults=1&api-version="
            + connection.getApiVersion();
        Http.Result result = call(url, token);
        if (result.ok()) {
            notes.add("The vault is reachable and this identity may list secrets.");
        } else if (result.status == 403) {
            notes.add("The vault is reachable, but this identity may not list secrets. "
                + "That is fine if it has been granted Get on the specific secrets you bind.");
        } else {
            throw new VaultException(Http.describe("Listing secrets", result));
        }
        return notes;
    }

    private Http.Result call(String url, String token) throws VaultException {
        try {
            return Http.get(url, Map.of("Authorization", "Bearer " + token,
                "Accept", "application/json"));
        } catch (IOException e) {
            throw new VaultException("Could not reach the vault: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // Tokens
    // ------------------------------------------------------------------

    private String token(VaultConnection connection) throws VaultException {
        CachedToken cached = tokens.get(connection.getId());
        if (cached != null && cached.isUsable()) {
            return cached.value;
        }
        CachedToken fresh = acquire(connection);
        tokens.put(connection.getId(), fresh);
        return fresh.value;
    }

    private CachedToken acquire(VaultConnection connection) throws VaultException {
        switch (connection.getAuthMode()) {
            case CLIENT_SECRET:
                return clientSecretToken(connection);
            case MANAGED_IDENTITY:
                return managedIdentityToken(connection);
            case WORKLOAD_IDENTITY:
                return workloadIdentityToken(connection);
            default:
                throw new VaultException(
                    VaultConnection.describeAuthMode(connection.getAuthMode())
                    + " cannot be used with Azure Key Vault.");
        }
    }

    private CachedToken clientSecretToken(VaultConnection connection) throws VaultException {
        String body = form(Map.of(
            "grant_type", "client_credentials",
            "client_id", connection.getClientId(),
            "client_secret", connection.getClientSecret(),
            "scope", SCOPE));
        return postForToken(tokenEndpoint(connection.getTenantId()), body,
            "Microsoft Entra ID");
    }

    /**
     * The identity the platform provides.
     *
     * <p>Two endpoints, not one. App Service, Functions and Container Apps inject
     * {@code IDENTITY_ENDPOINT} and a header secret; virtual machines and scale sets have
     * neither and are reached over IMDS on the link-local address. Trying the injected one
     * first matters because IMDS is also routable from inside those services and answers
     * for the wrong identity.
     */
    private CachedToken managedIdentityToken(VaultConnection connection) throws VaultException {
        String endpoint = System.getenv("IDENTITY_ENDPOINT");
        String header = System.getenv("IDENTITY_HEADER");
        try {
            Http.Result result;
            if (endpoint != null && !endpoint.isBlank() && header != null) {
                String url = endpoint + (endpoint.contains("?") ? "&" : "?")
                    + "api-version=2019-08-01&resource="
                    + URLEncoder.encode(RESOURCE, StandardCharsets.UTF_8)
                    + clientIdQuery(connection, "client_id");
                result = Http.getMetadata(url, Map.of("X-IDENTITY-HEADER", header));
            } else {
                String url = IMDS_TOKEN_URL + "&resource="
                    + URLEncoder.encode(RESOURCE, StandardCharsets.UTF_8)
                    + clientIdQuery(connection, "client_id");
                result = Http.getMetadata(url, Map.of("Metadata", "true"));
            }
            if (!result.ok()) {
                throw new VaultException(Http.describe("Requesting a managed identity token",
                    result));
            }
            return readToken(result.body);
        } catch (IOException e) {
            throw new VaultException("No managed identity is available here: "
                + e.getMessage() + ". Use a client secret unless this engine runs on Azure "
                + "with an identity assigned.", e);
        }
    }

    /** {@code &client_id=...} for a user-assigned identity, or nothing for the default. */
    private String clientIdQuery(VaultConnection connection, String parameter) {
        String clientId = connection.getClientId();
        if (clientId.isEmpty()) {
            return "";
        }
        return "&" + parameter + "=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8);
    }

    /**
     * AKS workload identity: the federated token from the pod, exchanged for an access
     * token as a client assertion.
     *
     * <p>The token file is rewritten by the kubelet as it approaches expiry, so it is read
     * on every acquisition rather than held.
     */
    private CachedToken workloadIdentityToken(VaultConnection connection) throws VaultException {
        String tokenFile = System.getenv("AZURE_FEDERATED_TOKEN_FILE");
        if (tokenFile == null || tokenFile.isBlank()) {
            throw new VaultException("AZURE_FEDERATED_TOKEN_FILE is not set, so this engine "
                + "is not running with workload identity. Check that the pod has the "
                + "azure.workload.identity/use label.");
        }
        String assertion;
        try {
            assertion = Files.readString(Path.of(tokenFile)).strip();
        } catch (IOException e) {
            throw new VaultException("Could not read the federated token at " + tokenFile
                + ": " + e.getMessage(), e);
        }

        // The webhook sets both of these in the pod, so the connection only has to carry
        // them when overriding it. env() rather than String.valueOf, which turns an unset
        // variable into the four characters "null" and sends them as a client id.
        String tenant = orEnv(connection.getTenantId(), "AZURE_TENANT_ID");
        String clientId = orEnv(connection.getClientId(), "AZURE_CLIENT_ID");
        if (clientId.isEmpty()) {
            throw new VaultException("Workload identity needs a client ID, either on the "
                + "connection or as AZURE_CLIENT_ID in the engine's environment.");
        }

        String body = form(new LinkedHashMap<>(Map.of(
            "grant_type", "client_credentials",
            "client_id", clientId,
            "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion", assertion,
            "scope", SCOPE)));
        return postForToken(tokenEndpoint(tenant), body, "Microsoft Entra ID");
    }

    /** The configured value, or the named environment variable, or empty. */
    private static String orEnv(String configured, String variable) {
        if (configured != null && !configured.isEmpty()) {
            return configured;
        }
        String value = System.getenv(variable);
        return value == null ? "" : value.strip();
    }

    private static String tokenEndpoint(String tenantId) {
        // "common" is the multi-tenant endpoint. It is the right fallback for a federated
        // credential, whose assertion names the tenant, and it fails clearly for a client
        // secret, which cannot be authenticated there.
        String tenant = tenantId == null || tenantId.isBlank() ? "common" : tenantId;
        return "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token";
    }

    private CachedToken postForToken(String url, String body, String what)
            throws VaultException {
        try {
            Http.Result result = Http.post(url,
                Map.of("Content-Type", "application/x-www-form-urlencoded",
                    "Accept", "application/json"),
                body);
            if (!result.ok()) {
                throw new VaultException(Http.describe("Authenticating with " + what, result));
            }
            return readToken(result.body);
        } catch (IOException e) {
            throw new VaultException("Could not reach " + what + ": " + e.getMessage(), e);
        }
    }

    /**
     * Reads a token response.
     *
     * <p>{@code expires_in} is relative seconds and {@code expires_on} is an absolute
     * epoch second; IMDS sends the latter and Entra ID the former, so both are handled.
     * A response with neither is treated as valid for five minutes, which costs an extra
     * token request an hour rather than failing.
     */
    private CachedToken readToken(String responseBody) throws VaultException {
        try {
            JsonNode node = Json.parse(responseBody);
            String token = Json.string(node, "access_token");
            if (token == null || token.isBlank()) {
                throw new VaultException("The token response carried no access_token.");
            }
            long expiresAt = System.currentTimeMillis() + 300_000L;
            String expiresIn = Json.string(node, "expires_in");
            String expiresOn = Json.string(node, "expires_on");
            if (expiresIn != null && expiresIn.matches("\\d+")) {
                expiresAt = System.currentTimeMillis() + Long.parseLong(expiresIn) * 1000L;
            } else if (expiresOn != null && expiresOn.matches("\\d+")) {
                expiresAt = Long.parseLong(expiresOn) * 1000L;
            }
            return new CachedToken(token, expiresAt);
        } catch (IOException e) {
            throw new VaultException("The token response could not be read.", e);
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
