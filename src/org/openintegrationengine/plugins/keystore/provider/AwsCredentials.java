/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

/**
 * An access key, and the moment it stops being one.
 *
 * <p>Immutable so that the credential a request is signed with cannot change between
 * building the canonical request and building the Authorization header -- a refresh on
 * another thread halfway through signing produces a signature mismatch that reads like a
 * clock skew problem and is very hard to find.
 */
public final class AwsCredentials {

    public final String accessKeyId;
    public final String secretAccessKey;
    /** Empty for long-lived keys; set for anything that came from STS or a role. */
    public final String sessionToken;
    /**
     * Epoch millis, or 0 for a credential that does not expire.
     *
     * <p>Only meaningful for temporary credentials. Long-lived keys are rotated by a human
     * and the engine has no way to know when that will be.
     */
    public final long expiresAt;

    public AwsCredentials(String accessKeyId, String secretAccessKey, String sessionToken,
                          long expiresAt) {
        this.accessKeyId = accessKeyId == null ? "" : accessKeyId;
        this.secretAccessKey = secretAccessKey == null ? "" : secretAccessKey;
        this.sessionToken = sessionToken == null ? "" : sessionToken;
        this.expiresAt = expiresAt;
    }

    public boolean isUsable() {
        return !accessKeyId.isEmpty() && !secretAccessKey.isEmpty();
    }

    /**
     * Whether these are close enough to expiry to be worth replacing.
     *
     * <p>The minute of slack matters: a credential that is valid when the request is
     * signed but expired by the time it reaches AWS fails with an authentication error
     * rather than anything that says "expired", so it is worth never getting that close.
     */
    public boolean isExpired() {
        return expiresAt > 0 && System.currentTimeMillis() > expiresAt - 60_000L;
    }
}
