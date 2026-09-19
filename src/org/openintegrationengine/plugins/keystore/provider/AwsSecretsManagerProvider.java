/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import com.fasterxml.jackson.databind.JsonNode;

import org.openintegrationengine.plugins.keystore.VaultConnection;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AWS Secrets Manager over its JSON protocol, signed with SigV4.
 *
 * <p>Two calls, {@code GetSecretValue} and {@code ListSecrets}, plus whatever STS work the
 * connection's auth mode needs first. The signing lives in {@link AwsV4Signer}; what is
 * here is the credential chain, which is the part that differs between a laptop, an ECS
 * task, an EC2 instance and an EKS pod.
 */
public final class AwsSecretsManagerProvider implements SecretProvider {

    private static final String SERVICE = "secretsmanager";
    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String STS_VERSION = "2011-06-15";

    private static final String IMDS_BASE = "http://169.254.169.254";

    /** Resolved credentials per connection, reused until they are close to expiring. */
    private final Map<String, AwsCredentials> credentials = new ConcurrentHashMap<>();

    @Override
    public VaultConnection.Type type() {
        return VaultConnection.Type.AWS_SECRETS_MANAGER;
    }

    /** Drops cached credentials, so an edited key or role takes effect at once. */
    public void forget(String connectionId) {
        credentials.remove(connectionId);
    }

    @Override
    public Secret fetch(VaultConnection connection, String secretId, String version)
            throws VaultException {
        String id = secretId == null ? "" : secretId.strip();
        if (id.isEmpty()) {
            throw new VaultException("No secret name or ARN was given.");
        }

        StringBuilder body = new StringBuilder("{\"SecretId\":").append(Json.quote(id));
        if (version != null && !version.isBlank()) {
            String v = version.strip();
            // A version id is a UUID; anything else is a stage label such as AWSCURRENT or
            // AWSPREVIOUS. Sending the wrong one of the two is an InvalidParameterException
            // rather than anything that hints at which field was meant.
            boolean looksLikeVersionId = v.matches(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            body.append(looksLikeVersionId ? ",\"VersionId\":" : ",\"VersionStage\":")
                .append(Json.quote(v));
        }
        body.append('}');

        Http.Result result = call(connection, "secretsmanager.GetSecretValue", body.toString());
        if (!result.ok()) {
            throw new VaultException(explain(result, id));
        }

        try {
            JsonNode node = Json.parse(result.body);
            String value = Json.string(node, "SecretString");
            if (value == null) {
                // A binary secret comes back as SecretBinary and is base64. Handing that
                // back as a password would be wrong, so it is refused with the reason.
                if (node.has("SecretBinary")) {
                    throw new VaultException("'" + id + "' is a binary secret. This plugin "
                        + "binds text secrets only.");
                }
                throw new VaultException("Secrets Manager returned no value for '" + id + "'.");
            }
            return new Secret(value, Json.string(node, "VersionId"));
        } catch (IOException e) {
            throw new VaultException("Secrets Manager returned a response that could not "
                + "be read.", e);
        }
    }

    /**
     * Turns an AWS error body into something worth reading.
     *
     * <p>The service answers 400 for almost everything, with the real reason in a
     * {@code __type} field. Left alone that surfaces in the console as "HTTP 400", which
     * says nothing about whether the secret is missing, the region is wrong or the policy
     * is.
     */
    private static String explain(Http.Result result, String id) {
        String type = "";
        try {
            String raw = Json.string(Json.parse(result.body), "__type");
            if (raw != null) {
                type = raw.contains("#") ? raw.substring(raw.indexOf('#') + 1) : raw;
            }
        } catch (IOException e) {
            // Not JSON, so the generic description below is all there is.
        }
        switch (type) {
            case "ResourceNotFoundException":
                return "Secrets Manager has no secret '" + id + "' in this region.";
            case "AccessDeniedException":
                return "Access denied reading '" + id + "'. The identity needs "
                    + "secretsmanager:GetSecretValue on it, and kms:Decrypt on the key it "
                    + "is encrypted with if that is a customer-managed key.";
            case "InvalidParameterException":
            case "InvalidRequestException":
                return "Secrets Manager rejected the request for '" + id + "': "
                    + Http.describe("GetSecretValue", result);
            case "UnrecognizedClientException":
            case "InvalidSignatureException":
                return "Secrets Manager rejected the credentials. Check the access key, "
                    + "and check the engine's clock -- a signature is refused if the host "
                    + "clock is more than five minutes out.";
            default:
                return Http.describe("Reading '" + id + "'", result);
        }
    }

    @Override
    public List<String> test(VaultConnection connection) throws VaultException {
        List<String> notes = new ArrayList<>();
        AwsCredentials creds = credentials(connection);
        notes.add("Resolved credentials for access key " + masked(creds.accessKeyId)
            + " using " + VaultConnection.describeAuthMode(connection.getAuthMode())
            + (connection.getRoleArn().isEmpty() ? "" : ", then assumed "
                + connection.getRoleArn()) + ".");

        Http.Result result = call(connection, "secretsmanager.ListSecrets",
            "{\"MaxResults\":1}");
        if (result.ok()) {
            notes.add("Secrets Manager in " + connection.getRegion()
                + " is reachable and this identity may list secrets.");
        } else if (result.body != null && result.body.contains("AccessDenied")) {
            // As with Key Vault, list and get are separate permissions and a
            // least-privilege policy grants only the second.
            notes.add("Secrets Manager is reachable, but this identity may not list "
                + "secrets. That is fine if it has GetSecretValue on the specific secrets "
                + "you bind.");
        } else {
            throw new VaultException(Http.describe("Listing secrets", result));
        }
        return notes;
    }

    /** Enough of an access key id to recognise, without printing the whole thing. */
    private static String masked(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.length() < 8) {
            return "(unknown)";
        }
        return accessKeyId.substring(0, 4) + "..."
            + accessKeyId.substring(accessKeyId.length() - 4);
    }

    private Http.Result call(VaultConnection connection, String target, String body)
            throws VaultException {
        AwsCredentials creds = credentials(connection);
        URI uri = URI.create(connection.secretsManagerEndpoint() + "/");

        Map<String, String> toSign = new LinkedHashMap<>();
        toSign.put("content-type", CONTENT_TYPE);
        toSign.put("x-amz-target", target);

        Map<String, String> headers = AwsV4Signer.sign("POST", uri, connection.getRegion(),
            SERVICE, toSign, body, creds);
        try {
            return Http.post(uri.toString(), headers, body);
        } catch (IOException e) {
            throw new VaultException("Could not reach " + uri.getHost() + ": "
                + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------

    private AwsCredentials credentials(VaultConnection connection) throws VaultException {
        AwsCredentials cached = credentials.get(connection.getId());
        if (cached != null && cached.isUsable() && !cached.isExpired()) {
            return cached;
        }

        AwsCredentials base = resolveBase(connection);
        if (!base.isUsable()) {
            throw new VaultException("No AWS credentials could be resolved for "
                + VaultConnection.describeAuthMode(connection.getAuthMode()) + ".");
        }
        AwsCredentials effective = connection.getRoleArn().isEmpty()
            ? base : assumeRole(connection, base);

        credentials.put(connection.getId(), effective);
        return effective;
    }

    private AwsCredentials resolveBase(VaultConnection connection) throws VaultException {
        switch (connection.getAuthMode()) {
            case STATIC_KEYS:
                return new AwsCredentials(connection.getAccessKeyId(),
                    connection.getSecretAccessKey(), connection.getSessionToken(), 0L);
            case ENVIRONMENT:
                return environmentCredentials();
            case INSTANCE_ROLE:
                return instanceCredentials();
            case WEB_IDENTITY:
                return webIdentityCredentials(connection);
            default:
                throw new VaultException(
                    VaultConnection.describeAuthMode(connection.getAuthMode())
                    + " cannot be used with AWS Secrets Manager.");
        }
    }

    private AwsCredentials environmentCredentials() throws VaultException {
        String key = System.getenv("AWS_ACCESS_KEY_ID");
        String secret = System.getenv("AWS_SECRET_ACCESS_KEY");
        if (key == null || secret == null) {
            throw new VaultException("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not "
                + "both set in the engine's environment.");
        }
        // Session credentials from the environment carry their own expiry, which is not
        // published anywhere the engine can read, so they are treated as non-expiring and
        // a failure is what prompts a refresh.
        return new AwsCredentials(key, secret, System.getenv("AWS_SESSION_TOKEN"), 0L);
    }

    /**
     * The role attached to the compute this engine runs on.
     *
     * <p>ECS and EKS pods are handed a credential relay through an environment variable;
     * EC2 has IMDS. The relay is tried first because it is present exactly when it is the
     * right answer, whereas IMDS answers on EC2 whether or not the task has its own role.
     */
    private AwsCredentials instanceCredentials() throws VaultException {
        String relative = System.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        String full = System.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
        try {
            if (relative != null && !relative.isBlank()) {
                return readContainerCredentials("http://169.254.170.2" + relative);
            }
            if (full != null && !full.isBlank()) {
                return readContainerCredentials(full);
            }
            return imdsCredentials();
        } catch (IOException e) {
            throw new VaultException("No instance or task role is available here: "
                + e.getMessage() + ". Use an access key unless this engine runs on AWS.", e);
        }
    }

    private AwsCredentials readContainerCredentials(String url)
            throws IOException, VaultException {
        Map<String, String> headers = new LinkedHashMap<>();
        String token = System.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
        String tokenFile = System.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
        if (tokenFile != null && !tokenFile.isBlank()) {
            token = Files.readString(Path.of(tokenFile)).strip();
        }
        if (token != null && !token.isBlank()) {
            headers.put("Authorization", token);
        }
        Http.Result result = Http.getMetadata(url, headers);
        if (!result.ok()) {
            throw new VaultException(Http.describe("Reading task role credentials", result));
        }
        return parseCredentialJson(result.body);
    }

    /**
     * EC2 instance credentials over IMDSv2.
     *
     * <p>Version 2 only. IMDSv1 is a plain GET with no token, which is exactly what makes
     * it reachable through a server-side request forgery in a channel, and instances are
     * increasingly configured to refuse it anyway.
     */
    private AwsCredentials imdsCredentials() throws IOException, VaultException {
        Http.Result tokenResult = Http.put(IMDS_BASE + "/latest/api/token",
            Map.of("X-aws-ec2-metadata-token-ttl-seconds", "300"), "");
        if (!tokenResult.ok()) {
            throw new VaultException("The instance metadata service did not issue a token. "
                + "IMDSv2 may be disabled, or this is not an EC2 instance.");
        }
        Map<String, String> headers = Map.of("X-aws-ec2-metadata-token", tokenResult.body.strip());

        Http.Result roleResult = Http.getMetadata(
            IMDS_BASE + "/latest/meta-data/iam/security-credentials/", headers);
        if (!roleResult.ok() || roleResult.body == null || roleResult.body.isBlank()) {
            throw new VaultException("This instance has no IAM role attached.");
        }
        String role = roleResult.body.strip().split("\\R")[0];

        Http.Result credsResult = Http.getMetadata(
            IMDS_BASE + "/latest/meta-data/iam/security-credentials/"
            + URLEncoder.encode(role, StandardCharsets.UTF_8), headers);
        if (!credsResult.ok()) {
            throw new VaultException(Http.describe("Reading instance credentials", credsResult));
        }
        return parseCredentialJson(credsResult.body);
    }

    /** The shape IMDS and the ECS relay both use. */
    private AwsCredentials parseCredentialJson(String body) throws VaultException {
        try {
            JsonNode node = Json.parse(body);
            return new AwsCredentials(
                Json.string(node, "AccessKeyId"),
                Json.string(node, "SecretAccessKey"),
                Json.string(node, "Token"),
                parseIso8601(Json.string(node, "Expiration")));
        } catch (IOException e) {
            throw new VaultException("Instance credentials could not be read.", e);
        }
    }

    /**
     * EKS IAM roles for service accounts.
     *
     * <p>AssumeRoleWithWebIdentity needs no credentials of its own -- the projected
     * service account token is the proof -- so this is the one STS call here that is sent
     * unsigned.
     */
    private AwsCredentials webIdentityCredentials(VaultConnection connection)
            throws VaultException {
        String tokenFile = System.getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
        String roleArn = System.getenv("AWS_ROLE_ARN");
        if (tokenFile == null || tokenFile.isBlank() || roleArn == null || roleArn.isBlank()) {
            throw new VaultException("AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN are not "
                + "both set, so this engine is not running with an IAM role for a service "
                + "account.");
        }
        String assertion;
        try {
            assertion = Files.readString(Path.of(tokenFile)).strip();
        } catch (IOException e) {
            throw new VaultException("Could not read the web identity token at " + tokenFile
                + ": " + e.getMessage(), e);
        }

        String body = form(Map.of(
            "Action", "AssumeRoleWithWebIdentity",
            "Version", STS_VERSION,
            "RoleArn", roleArn,
            "RoleSessionName", sessionName(),
            "WebIdentityToken", assertion));
        try {
            Http.Result result = Http.post(stsEndpoint(connection),
                Map.of("Content-Type", "application/x-www-form-urlencoded"), body);
            if (!result.ok()) {
                throw new VaultException(Http.describe("AssumeRoleWithWebIdentity", result));
            }
            return parseStsXml(result.body);
        } catch (IOException e) {
            throw new VaultException("Could not reach STS: " + e.getMessage(), e);
        }
    }

    /** Assumes {@code roleArn}, signed with the credentials already resolved. */
    private AwsCredentials assumeRole(VaultConnection connection, AwsCredentials base)
            throws VaultException {
        String body = form(Map.of(
            "Action", "AssumeRole",
            "Version", STS_VERSION,
            "RoleArn", connection.getRoleArn(),
            "RoleSessionName", sessionName()));
        URI uri = URI.create(stsEndpoint(connection));

        Map<String, String> headers = AwsV4Signer.sign("POST", uri, connection.getRegion(),
            "sts", Map.of("content-type", "application/x-www-form-urlencoded"), body, base);
        try {
            Http.Result result = Http.post(uri.toString(), headers, body);
            if (!result.ok()) {
                throw new VaultException(Http.describe(
                    "Assuming " + connection.getRoleArn(), result));
            }
            return parseStsXml(result.body);
        } catch (IOException e) {
            throw new VaultException("Could not reach STS: " + e.getMessage(), e);
        }
    }

    /**
     * The regional STS endpoint.
     *
     * <p>Regional rather than the global one: the global endpoint is not enabled in every
     * region by default, and a session token minted globally is rejected in regions that
     * have not opted in.
     */
    private static String stsEndpoint(VaultConnection connection) {
        return "https://sts." + connection.getRegion() + ".amazonaws.com/";
    }

    /**
     * A session name that shows up in CloudTrail as something identifiable.
     *
     * <p>STS restricts this to a fairly narrow character set, so anything unexpected in
     * the hostname is replaced rather than passed through into a request that would be
     * rejected for a reason that has nothing to do with the role.
     */
    private static String sessionName() {
        String host = System.getenv("HOSTNAME");
        String suffix = host == null ? "" : "-" + host.replaceAll("[^\\w+=,.@-]", "");
        String name = "oie-key-store" + suffix;
        return name.length() > 64 ? name.substring(0, 64) : name;
    }

    // STS answers the query protocol in XML. Three fields are wanted out of it and the
    // engine's XML parsers all want a document model; regex is the smaller thing to
    // maintain for a response whose shape is fixed by an API version in the request.
    private static final Pattern ACCESS_KEY = Pattern.compile("<AccessKeyId>(.*?)</AccessKeyId>");
    private static final Pattern SECRET_KEY =
        Pattern.compile("<SecretAccessKey>(.*?)</SecretAccessKey>");
    private static final Pattern SESSION_TOKEN =
        Pattern.compile("<SessionToken>(.*?)</SessionToken>", Pattern.DOTALL);
    private static final Pattern EXPIRATION = Pattern.compile("<Expiration>(.*?)</Expiration>");

    private static AwsCredentials parseStsXml(String xml) throws VaultException {
        String key = group(ACCESS_KEY, xml);
        String secret = group(SECRET_KEY, xml);
        if (key == null || secret == null) {
            throw new VaultException("STS returned a response with no credentials in it.");
        }
        return new AwsCredentials(key, secret, group(SESSION_TOKEN, xml),
            parseIso8601(group(EXPIRATION, xml)));
    }

    private static String group(Pattern pattern, String text) {
        if (text == null) {
            return null;
        }
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).strip() : null;
    }

    /** @return epoch millis, or 0 when the timestamp is absent or unreadable */
    private static long parseIso8601(String text) {
        if (text == null || text.isBlank()) {
            return 0L;
        }
        try {
            return java.time.Instant.parse(text.strip()).toEpochMilli();
        } catch (Exception e) {
            // Treated as non-expiring: refreshing too rarely is recoverable, whereas
            // treating a good credential as expired would re-assume the role every call.
            return 0L;
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
