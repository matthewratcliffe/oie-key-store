/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * The one HTTP client the providers share.
 *
 * <p>{@link java.net.http.HttpClient} rather than a vendor SDK. The engine already ships
 * an AWS SDK (2.15.28, for S3 and KMS) but not its Secrets Manager module, and bringing a
 * newer module alongside a 2020 core is the kind of split that works until the day it
 * does not. Both providers here speak documented, stable HTTPS APIs, so the JDK's own
 * client covers them and this extension bundles no third-party jars at all.
 *
 * <p>Timeouts are short and always set. A secret refresh runs on a scheduler thread, and
 * an unbounded read against an unreachable vault endpoint would hold that thread for as
 * long as the OS lets it -- which is how a single misconfigured connection stops every
 * other connection from ever refreshing.
 */
public final class Http {

    /** Long enough for a TLS handshake to a cloud endpoint, short enough to fail a pass. */
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);

    /**
     * Metadata endpoints (IMDS, ECS credential relay) are on the local link and must never
     * be given the generous timeout a cloud endpoint gets: when there is no metadata
     * service -- which is every developer laptop -- the connect simply hangs.
     */
    private static final Duration METADATA_TIMEOUT = Duration.ofSeconds(3);

    /**
     * One client for the JVM. It pools connections, and a vault is asked for the same
     * handful of secrets on a timer, so a per-request client would mean a new TLS
     * handshake every time for no gain.
     *
     * <p>Redirects are never followed. A 302 on a token or secret request would send a
     * bearer token or a signed Authorization header to whatever host the response names,
     * which is the one thing this code must not do.
     */
    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(CONNECT_TIMEOUT)
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private Http() {
    }

    /** A response body plus the status that came with it. */
    public static final class Result {
        public final int status;
        public final String body;

        Result(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    public static Result get(String url, Map<String, String> headers) throws IOException {
        return send(builder(url, REQUEST_TIMEOUT, headers).GET().build());
    }

    /** A GET against a link-local metadata service, on the short timeout. */
    public static Result getMetadata(String url, Map<String, String> headers) throws IOException {
        return send(builder(url, METADATA_TIMEOUT, headers).GET().build());
    }

    public static Result put(String url, Map<String, String> headers, String body)
            throws IOException {
        return send(builder(url, METADATA_TIMEOUT, headers)
            .PUT(HttpRequest.BodyPublishers.ofString(body)).build());
    }

    public static Result post(String url, Map<String, String> headers, String body)
            throws IOException {
        return send(builder(url, REQUEST_TIMEOUT, headers)
            .POST(HttpRequest.BodyPublishers.ofString(body)).build());
    }

    private static HttpRequest.Builder builder(String url, Duration timeout,
                                               Map<String, String> headers) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(timeout);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getValue() != null) {
                    b.header(e.getKey(), e.getValue());
                }
            }
        }
        return b;
    }

    private static Result send(HttpRequest request) throws IOException {
        try {
            HttpResponse<String> response =
                CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            return new Result(response.statusCode(), response.body());
        } catch (InterruptedException e) {
            // Restored so a shutdown that interrupts a refresh still stops the scheduler
            // rather than being swallowed here and having to be noticed again later.
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while calling " + request.uri().getHost(), e);
        }
    }

    /**
     * A failure message safe to show an administrator.
     *
     * <p>The body is truncated and the host is named, because "403 Forbidden" on its own
     * has sent people to the wrong vault more than once. It is not scrubbed beyond that:
     * these are error bodies from the vault's own API, which carry request ids and policy
     * names, not secret values -- a successful fetch is the only response that carries one
     * and it never reaches here.
     */
    public static String describe(String what, Result r) {
        String body = r.body == null ? "" : r.body.strip();
        if (body.length() > 400) {
            body = body.substring(0, 400) + "...";
        }
        return what + " failed: HTTP " + r.status + (body.isEmpty() ? "" : " -- " + body);
    }
}
