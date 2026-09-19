/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * AWS Signature Version 4, for the two calls this plugin makes.
 *
 * <p>Hand-written rather than taken from an SDK. The engine ships AWS SDK 2.15.28 for S3
 * and KMS but not its Secrets Manager module, and adding a current module beside a 2020
 * core is the sort of split that works right up until a shared class changes underneath
 * it. SigV4 itself has not changed since 2012 and is about eighty lines, so this is the
 * smaller liability.
 *
 * <p>Only the cases that arise here are covered: a single-path request with no query
 * string and a body already in hand. Neither Secrets Manager nor STS needs more, and
 * covering the general case would mean writing canonicalisation rules with nothing
 * exercising them.
 */
public final class AwsV4Signer {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String TERMINATOR = "aws4_request";

    private static final DateTimeFormatter AMZ_DATE =
        DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_STAMP =
        DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private AwsV4Signer() {
    }

    /**
     * Signs a request and returns every header it should be sent with.
     *
     * <p>The returned map includes the headers that were signed, because a signed header
     * that is not sent -- or is sent with a different value -- fails with the same opaque
     * "signature we calculated does not match" as a wrong secret key. Handing back the
     * complete set is the only way to keep the two in step.
     *
     * @param extraHeaders headers to sign beyond host and date, such as x-amz-target;
     *                     names are lowercased, and values must be sent exactly as given
     */
    public static Map<String, String> sign(String method, URI uri, String region,
                                           String service, Map<String, String> extraHeaders,
                                           String payload, AwsCredentials credentials) {
        Instant now = Instant.now();
        String amzDate = AMZ_DATE.format(now);
        String dateStamp = DATE_STAMP.format(now);

        // Sorted, lowercase, because the canonical request and the SignedHeaders list must
        // agree on both order and case and a TreeMap makes that automatic rather than
        // something to remember in two places.
        Map<String, String> signed = new TreeMap<>();
        signed.put("host", hostHeader(uri));
        signed.put("x-amz-date", amzDate);
        if (extraHeaders != null) {
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                if (e.getValue() != null) {
                    signed.put(e.getKey().toLowerCase(java.util.Locale.ROOT), e.getValue().trim());
                }
            }
        }
        if (!credentials.sessionToken.isEmpty()) {
            // Temporary credentials are only accepted when the token is part of the
            // signature, not merely sent alongside it.
            signed.put("x-amz-security-token", credentials.sessionToken);
        }

        String canonicalHeaders = canonicalHeaders(signed);
        String signedHeaderNames = String.join(";", signed.keySet());
        String payloadHash = hex(sha256(payload == null ? "" : payload));

        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty()
            ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : uri.getRawQuery();

        String canonicalRequest = String.join("\n",
            method,
            path,
            query,
            canonicalHeaders,
            signedHeaderNames,
            payloadHash);

        String scope = dateStamp + "/" + region + "/" + service + "/" + TERMINATOR;
        String stringToSign = String.join("\n",
            ALGORITHM,
            amzDate,
            scope,
            hex(sha256(canonicalRequest)));

        byte[] signingKey = signingKey(credentials.secretAccessKey, dateStamp, region, service);
        String signature = hex(hmac(signingKey, stringToSign));

        Map<String, String> out = new LinkedHashMap<>(signed);
        out.put("Authorization", ALGORITHM
            + " Credential=" + credentials.accessKeyId + "/" + scope
            + ", SignedHeaders=" + signedHeaderNames
            + ", Signature=" + signature);
        return out;
    }

    /**
     * The Host header as the JDK's client will actually send it.
     *
     * <p>The default port is left off. Including {@code :443} here while the client sends
     * a bare host is a signature mismatch, and it is not obvious from the error which of
     * the two sides is wrong.
     */
    private static String hostHeader(URI uri) {
        int port = uri.getPort();
        boolean defaultPort = port == -1
            || (port == 443 && "https".equalsIgnoreCase(uri.getScheme()))
            || (port == 80 && "http".equalsIgnoreCase(uri.getScheme()));
        return defaultPort ? uri.getHost() : uri.getHost() + ":" + port;
    }

    /**
     * Header lines for the canonical request.
     *
     * <p>Runs of whitespace inside a value collapse to one space, per the specification.
     * None of the values sent here contain any, but leaving it out would make this correct
     * only by accident.
     */
    private static String canonicalHeaders(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            sb.append(e.getKey()).append(':')
              .append(e.getValue().trim().replaceAll("\\s+", " "))
              .append('\n');
        }
        return sb.toString();
    }

    private static byte[] signingKey(String secretAccessKey, String dateStamp, String region,
                                     String service) {
        byte[] key = ("AWS4" + secretAccessKey).getBytes(StandardCharsets.UTF_8);
        byte[] date = hmac(key, dateStamp);
        byte[] regional = hmac(date, region);
        byte[] serviced = hmac(regional, service);
        return hmac(serviced, TERMINATOR);
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            // HmacSHA256 is required of every JRE. If it is genuinely missing, nothing
            // this plugin does can work and there is no sensible fallback to attempt.
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static byte[] sha256(String data) {
        try {
            return MessageDigest.getInstance("SHA-256")
                .digest(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
