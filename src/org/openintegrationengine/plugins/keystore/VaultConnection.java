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
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * One configured vault: where it is, and how this engine proves who it is to it.
 *
 * <p>Several connections are allowed on purpose rather than one per provider. A single
 * engine routinely talks to more than one account -- a partner's Key Vault beside your
 * own, or separate AWS accounts for two payers -- and collapsing those into one set of
 * credentials is what makes people paste a production key into a test instance.
 *
 * <p>Stored as one line of percent-encoded {@code name=value} pairs rather than positional
 * fields. The four providers do not share a field list and none of the lists is finished,
 * so a positional row would need either a column for every field any provider might ever
 * have or a new format version each time one is added. Named pairs make an unknown key a
 * no-op instead of a corrupt row.
 *
 * <p>The credential fields hold ciphertext, not plaintext: {@link VaultConnectionStore}
 * encrypts them with the engine's own encryptor on the way in and decrypts them on the way
 * out, so what sits in the {@code configuration} table is not usable on its own.
 */
public final class VaultConnection {

    /** Which vault this talks to. */
    public enum Type {
        AZURE_KEY_VAULT,
        AWS_SECRETS_MANAGER,
        /**
         * 1Password through a Connect server. Connect is the only 1Password interface a
         * long-running server process can use without a CLI on the host: service accounts
         * are reached through the SDK or {@code op}, and shelling out to a binary that has
         * to be installed into the engine image is a worse dependency than an HTTP call.
         */
        ONEPASSWORD_CONNECT,
        BITWARDEN_SECRETS_MANAGER
    }

    /** How the engine proves who it is. Which values apply differs by {@link Type}. */
    public enum AuthMode {
        /** Azure: an app registration's client secret. */
        CLIENT_SECRET,
        /**
         * Azure: the platform-provided identity -- App Service and Container Apps via
         * {@code IDENTITY_ENDPOINT}, otherwise the IMDS endpoint on a VM or VMSS.
         */
        MANAGED_IDENTITY,
        /**
         * Azure: AKS workload identity. The projected service account token is exchanged
         * for an access token as a client assertion, so the engine holds no secret.
         */
        WORKLOAD_IDENTITY,
        /** AWS: an access key held by this plugin. */
        STATIC_KEYS,
        /** AWS: {@code AWS_ACCESS_KEY_ID} and friends from the engine's environment. */
        ENVIRONMENT,
        /** AWS: the ECS task role, or the EC2 instance role over IMDSv2. */
        INSTANCE_ROLE,
        /** AWS: EKS IAM roles for service accounts, via AssumeRoleWithWebIdentity. */
        WEB_IDENTITY,
        /** 1Password: a Connect server access token. */
        CONNECT_TOKEN,
        /** Bitwarden: a Secrets Manager machine account access token. */
        ACCESS_TOKEN
    }

    private String id = UUID.randomUUID().toString();
    private String name = "";
    private Type type = Type.AZURE_KEY_VAULT;
    private boolean enabled = true;
    private AuthMode authMode = AuthMode.CLIENT_SECRET;

    // -- Azure ---------------------------------------------------------

    /** {@code https://NAME.vault.azure.net}, stored without a trailing slash. */
    private String vaultUrl = "";
    private String tenantId = "";
    private String clientId = "";
    /** Ciphertext at rest; plaintext only on an instance loaded through the store. */
    private String clientSecret = "";
    /**
     * Pinned rather than left at "latest" so a change to the current API version cannot
     * alter a response shape underneath a running engine. Overridable because a sovereign
     * cloud may be behind the public one.
     */
    private String apiVersion = "7.4";

    // -- AWS -----------------------------------------------------------

    private String region = "";
    private String accessKeyId = "";
    /** Ciphertext at rest. */
    private String secretAccessKey = "";
    /** Ciphertext at rest. Only meaningful alongside temporary keys. */
    private String sessionToken = "";
    /**
     * Assumed after the base credential is resolved, when set. This is how one engine
     * reads a secret owned by another account without holding that account's keys.
     */
    private String roleArn = "";
    /** For VPC endpoints, GovCloud, or a Secrets Manager emulator under test. */
    private String endpointOverride = "";

    // -- 1Password Connect ---------------------------------------------

    /** The Connect server's base URL, for example {@code http://onepassword-connect:8080}. */
    private String connectUrl = "";
    /** Ciphertext at rest. The Connect token, which is scoped to specific vaults. */
    private String connectToken = "";

    // -- Bitwarden Secrets Manager -------------------------------------

    /** Ciphertext at rest. The whole access token, including its encryption key part. */
    private String accessToken = "";
    /** Defaulted per region; overridden for a self-hosted server. */
    private String identityUrl = "";
    private String apiUrl = "";
    /**
     * Optional. Normally read from the {@code organization} claim of the token the
     * identity endpoint returns, which is the only place a machine account is told which
     * organisation it belongs to.
     */
    private String organizationId = "";

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    public String getId() {
        return id;
    }

    public void setId(String id) {
        if (id != null && !id.isBlank()) {
            this.id = id.trim();
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name == null ? "" : name.strip();
    }

    /** The name if there is one, otherwise something that still identifies it in a log. */
    public String label() {
        if (!name.isEmpty()) {
            return name;
        }
        switch (type) {
            case AZURE_KEY_VAULT:
                return vaultUrl.isEmpty() ? id : vaultUrl;
            case AWS_SECRETS_MANAGER:
                return region.isEmpty() ? id : "AWS " + region;
            case ONEPASSWORD_CONNECT:
                return connectUrl.isEmpty() ? id : connectUrl;
            case BITWARDEN_SECRETS_MANAGER:
                return organizationId.isEmpty() ? id : "Bitwarden " + organizationId;
            default:
                return id;
        }
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        if (type != null && type != this.type) {
            this.type = type;
            // The previous provider's auth mode is meaningless on the new one, and leaving
            // it would make the connection fail with "unsupported auth mode" rather than
            // simply asking for what the new provider needs.
            this.authMode = defaultAuthMode(type);
        }
    }

    public static AuthMode defaultAuthMode(Type type) {
        switch (type) {
            case AWS_SECRETS_MANAGER:
                return AuthMode.STATIC_KEYS;
            case ONEPASSWORD_CONNECT:
                return AuthMode.CONNECT_TOKEN;
            case BITWARDEN_SECRETS_MANAGER:
                return AuthMode.ACCESS_TOKEN;
            default:
                return AuthMode.CLIENT_SECRET;
        }
    }

    /** The auth modes that apply to a type, in the order the editor should offer them. */
    public static List<AuthMode> authModesFor(Type type) {
        switch (type) {
            case AWS_SECRETS_MANAGER:
                return List.of(AuthMode.STATIC_KEYS, AuthMode.ENVIRONMENT,
                    AuthMode.INSTANCE_ROLE, AuthMode.WEB_IDENTITY);
            case ONEPASSWORD_CONNECT:
                return List.of(AuthMode.CONNECT_TOKEN);
            case BITWARDEN_SECRETS_MANAGER:
                return List.of(AuthMode.ACCESS_TOKEN);
            default:
                return List.of(AuthMode.CLIENT_SECRET, AuthMode.MANAGED_IDENTITY,
                    AuthMode.WORKLOAD_IDENTITY);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public AuthMode getAuthMode() {
        return authMode;
    }

    public void setAuthMode(AuthMode authMode) {
        if (authMode != null) {
            this.authMode = authMode;
        }
    }

    /** The vault base URL with no trailing slash, so callers can append a path safely. */
    public String getVaultUrl() {
        return vaultUrl;
    }

    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = trimTrailingSlashes(vaultUrl);
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId == null ? "" : tenantId.strip();
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId == null ? "" : clientId.strip();
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret == null ? "" : clientSecret;
    }

    public String getApiVersion() {
        return apiVersion.isEmpty() ? "7.4" : apiVersion;
    }

    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion == null ? "" : apiVersion.strip();
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region == null ? "" : region.strip().toLowerCase(Locale.ROOT);
    }

    public String getAccessKeyId() {
        return accessKeyId;
    }

    public void setAccessKeyId(String accessKeyId) {
        this.accessKeyId = accessKeyId == null ? "" : accessKeyId.strip();
    }

    public String getSecretAccessKey() {
        return secretAccessKey;
    }

    public void setSecretAccessKey(String secretAccessKey) {
        this.secretAccessKey = secretAccessKey == null ? "" : secretAccessKey.strip();
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken == null ? "" : sessionToken.strip();
    }

    public String getRoleArn() {
        return roleArn;
    }

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn == null ? "" : roleArn.strip();
    }

    public String getEndpointOverride() {
        return endpointOverride;
    }

    public void setEndpointOverride(String endpointOverride) {
        this.endpointOverride = trimTrailingSlashes(endpointOverride);
    }

    /** The Secrets Manager endpoint for this connection. */
    public String secretsManagerEndpoint() {
        return endpointOverride.isEmpty()
            ? "https://secretsmanager." + region + ".amazonaws.com"
            : endpointOverride;
    }

    public String getConnectUrl() {
        return connectUrl;
    }

    public void setConnectUrl(String connectUrl) {
        this.connectUrl = trimTrailingSlashes(connectUrl);
    }

    public String getConnectToken() {
        return connectToken;
    }

    public void setConnectToken(String connectToken) {
        this.connectToken = connectToken == null ? "" : connectToken.strip();
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken == null ? "" : accessToken.strip();
    }

    public String getIdentityUrl() {
        return identityUrl.isEmpty() ? "https://identity.bitwarden.com" : identityUrl;
    }

    public void setIdentityUrl(String identityUrl) {
        this.identityUrl = trimTrailingSlashes(identityUrl);
    }

    public String getApiUrl() {
        return apiUrl.isEmpty() ? "https://api.bitwarden.com" : apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = trimTrailingSlashes(apiUrl);
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId == null ? "" : organizationId.strip();
    }

    /** Whether this connection's auth mode needs a credential the plugin has to store. */
    public boolean holdsCredential() {
        return authMode == AuthMode.CLIENT_SECRET
            || authMode == AuthMode.STATIC_KEYS
            || authMode == AuthMode.CONNECT_TOKEN
            || authMode == AuthMode.ACCESS_TOKEN;
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /**
     * What is missing, in words an administrator can act on.
     *
     * <p>Checked before saving rather than at first use. A connection that fails only when
     * a channel deploys at 3am is a connection nobody finds until it matters.
     */
    public List<String> problems() {
        List<String> out = new ArrayList<>();
        if (name.isEmpty()) {
            out.add("Give the connection a name.");
        }
        if (!authModesFor(type).contains(authMode)) {
            out.add(describeAuthMode(authMode) + " is not available for "
                + describeType(type) + ".");
        }
        switch (type) {
            case AZURE_KEY_VAULT:
                azureProblems(out);
                break;
            case AWS_SECRETS_MANAGER:
                awsProblems(out);
                break;
            case ONEPASSWORD_CONNECT:
                onePasswordProblems(out);
                break;
            case BITWARDEN_SECRETS_MANAGER:
                bitwardenProblems(out);
                break;
            default:
                break;
        }
        return out;
    }

    private void azureProblems(List<String> out) {
        if (vaultUrl.isEmpty()) {
            out.add("A vault URL is required, for example https://contoso.vault.azure.net.");
        } else if (!vaultUrl.startsWith("https://")) {
            // Not pedantry: a bearer token over http would be readable on the wire, and
            // Key Vault does not serve http anyway.
            out.add("The vault URL must start with https://.");
        }
        if (authMode == AuthMode.CLIENT_SECRET) {
            if (tenantId.isEmpty()) {
                out.add("A directory (tenant) ID is required for a client secret.");
            }
            if (clientId.isEmpty()) {
                out.add("An application (client) ID is required for a client secret.");
            }
        }
        if (authMode == AuthMode.WORKLOAD_IDENTITY && clientId.isEmpty()
            && System.getenv("AZURE_CLIENT_ID") == null) {
            out.add("Workload identity needs a client ID, either here or as AZURE_CLIENT_ID "
                + "in the engine's environment.");
        }
    }

    private void awsProblems(List<String> out) {
        if (region.isEmpty()) {
            out.add("An AWS region is required, for example ap-southeast-2.");
        }
        if (authMode == AuthMode.STATIC_KEYS && accessKeyId.isEmpty()) {
            out.add("An access key ID is required for static keys.");
        }
        if (!endpointOverride.isEmpty() && !endpointOverride.startsWith("https://")
            && !endpointOverride.startsWith("http://")) {
            out.add("The endpoint override must be a URL.");
        }
    }

    private void onePasswordProblems(List<String> out) {
        if (connectUrl.isEmpty()) {
            out.add("A Connect server URL is required, for example "
                + "http://onepassword-connect:8080.");
        } else if (!connectUrl.startsWith("https://") && !connectUrl.startsWith("http://")) {
            out.add("The Connect server URL must be a URL.");
        }
        // Connect is frequently run as a sidecar on a private network, so plain http is a
        // real deployment and not worth refusing -- but it is worth saying out loud, since
        // the token in the Authorization header is bearer credentials in clear text.
        if (connectUrl.startsWith("http://") && !isLoopback(connectUrl)) {
            out.add("Warning: this Connect URL is plain http, so the access token is sent "
                + "unencrypted. Use https unless the server is on the same host.");
        }
    }

    private void bitwardenProblems(List<String> out) {
        if (accessToken.isEmpty()) {
            out.add("A Secrets Manager access token is required.");
        } else if (!accessToken.startsWith("0.") || !accessToken.contains(":")) {
            // Checked here rather than at first use because the shape is the one thing
            // that can be verified without contacting Bitwarden, and a truncated paste is
            // by far the most common way this goes wrong.
            out.add("That does not look like an access token. It should start with "
                + "\"0.\" and contain a colon before its encryption key.");
        }
        if (!identityUrl.isEmpty() && !identityUrl.startsWith("http")) {
            out.add("The identity URL must be a URL.");
        }
        if (!apiUrl.isEmpty() && !apiUrl.startsWith("http")) {
            out.add("The API URL must be a URL.");
        }
    }

    private static boolean isLoopback(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://localhost")
            || lower.startsWith("http://127.")
            || lower.startsWith("http://[::1]");
    }

    public static String describeType(Type type) {
        switch (type) {
            case AWS_SECRETS_MANAGER:
                return "AWS Secrets Manager";
            case ONEPASSWORD_CONNECT:
                return "1Password Connect";
            case BITWARDEN_SECRETS_MANAGER:
                return "Bitwarden Secrets Manager";
            default:
                return "Azure Key Vault";
        }
    }

    public static String describeAuthMode(AuthMode mode) {
        switch (mode) {
            case CLIENT_SECRET:
                return "Client secret";
            case MANAGED_IDENTITY:
                return "Managed identity";
            case WORKLOAD_IDENTITY:
                return "Workload identity";
            case STATIC_KEYS:
                return "Access key";
            case ENVIRONMENT:
                return "Environment variables";
            case INSTANCE_ROLE:
                return "Instance or task role";
            case WEB_IDENTITY:
                return "IAM role for service account";
            case CONNECT_TOKEN:
                return "Connect token";
            case ACCESS_TOKEN:
                return "Access token";
            default:
                return mode.name();
        }
    }

    /**
     * How a secret is named for this provider, for the binding editor's hint.
     *
     * <p>The four disagree completely -- a bare name, an ARN, a path through a vault, a
     * UUID -- and getting it wrong is the most likely reason a binding fails, so the
     * editor says it rather than leaving it to the documentation.
     */
    public static String describeSecretIdFormat(Type type) {
        switch (type) {
            case AWS_SECRETS_MANAGER:
                return "The secret's name or full ARN, for example prod/hl7/partner-api.";
            case ONEPASSWORD_CONNECT:
                return "Vault and item, optionally with a field: "
                    + "Production/Partner API/credential. Names or UUIDs both work, and an "
                    + "op://vault/item/field reference may be pasted as it stands.";
            case BITWARDEN_SECRETS_MANAGER:
                return "The secret's key, or its UUID.";
            default:
                return "The secret's name in the vault, for example partner-api-token.";
        }
    }

    // ------------------------------------------------------------------
    // Serialisation
    // ------------------------------------------------------------------

    /** The stored form: percent-encoded {@code name=value} pairs joined by ampersands. */
    public String serialise() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("id", id);
        fields.put("name", name);
        fields.put("type", type.name());
        fields.put("enabled", Boolean.toString(enabled));
        fields.put("authMode", authMode.name());
        fields.put("vaultUrl", vaultUrl);
        fields.put("tenantId", tenantId);
        fields.put("clientId", clientId);
        fields.put("clientSecret", clientSecret);
        fields.put("apiVersion", apiVersion);
        fields.put("region", region);
        fields.put("accessKeyId", accessKeyId);
        fields.put("secretAccessKey", secretAccessKey);
        fields.put("sessionToken", sessionToken);
        fields.put("roleArn", roleArn);
        fields.put("endpointOverride", endpointOverride);
        fields.put("connectUrl", connectUrl);
        fields.put("connectToken", connectToken);
        fields.put("accessToken", accessToken);
        fields.put("identityUrl", identityUrl);
        fields.put("apiUrl", apiUrl);
        fields.put("organizationId", organizationId);

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

    /**
     * Reads a connection back.
     *
     * @return the connection, or null when the line is empty or carries no id -- an
     *     unreadable row is dropped with a warning rather than failing the whole load
     */
    public static VaultConnection parse(String line) {
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

        VaultConnection c = new VaultConnection();
        c.setId(fields.get("id"));
        c.setName(fields.getOrDefault("name", ""));
        // Assigned directly rather than through setType, whose side effect of resetting
        // the auth mode is right in the editor and wrong when reading a stored row back.
        c.type = parseEnum(Type.class, fields.get("type"), Type.AZURE_KEY_VAULT);
        c.enabled = !"false".equalsIgnoreCase(fields.getOrDefault("enabled", "true"));
        c.authMode = parseEnum(AuthMode.class, fields.get("authMode"), defaultAuthMode(c.type));
        c.setVaultUrl(fields.getOrDefault("vaultUrl", ""));
        c.setTenantId(fields.getOrDefault("tenantId", ""));
        c.setClientId(fields.getOrDefault("clientId", ""));
        c.clientSecret = fields.getOrDefault("clientSecret", "");
        c.setApiVersion(fields.getOrDefault("apiVersion", ""));
        c.setRegion(fields.getOrDefault("region", ""));
        c.setAccessKeyId(fields.getOrDefault("accessKeyId", ""));
        c.secretAccessKey = fields.getOrDefault("secretAccessKey", "");
        c.sessionToken = fields.getOrDefault("sessionToken", "");
        c.setRoleArn(fields.getOrDefault("roleArn", ""));
        c.setEndpointOverride(fields.getOrDefault("endpointOverride", ""));
        c.setConnectUrl(fields.getOrDefault("connectUrl", ""));
        c.connectToken = fields.getOrDefault("connectToken", "");
        c.accessToken = fields.getOrDefault("accessToken", "");
        c.setIdentityUrl(fields.getOrDefault("identityUrl", ""));
        c.setApiUrl(fields.getOrDefault("apiUrl", ""));
        c.setOrganizationId(fields.getOrDefault("organizationId", ""));
        return c;
    }

    public static <E extends Enum<E>> E parseEnum(Class<E> type, String value, E fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Enum.valueOf(type, value.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }

    private static String trimTrailingSlashes(String value) {
        String v = value == null ? "" : value.strip();
        while (v.endsWith("/")) {
            v = v.substring(0, v.length() - 1);
        }
        return v;
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // A value that is not valid percent-encoding is returned as it stands rather
            // than taking out the whole connection; the worst case is one odd-looking field.
            return s;
        }
    }
}
