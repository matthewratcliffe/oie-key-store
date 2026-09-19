/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * The cryptography Bitwarden Secrets Manager requires of a client.
 *
 * <p>Secrets Manager is zero-knowledge: the API returns every key, value and note as
 * ciphertext, and the organisation's symmetric key arrives encrypted under a key derived
 * from the access token. So unlike the other three providers, reading a Bitwarden secret
 * is not a matter of making the right HTTP call -- the decryption has to happen here.
 *
 * <p>Two pieces, both from Bitwarden's published SDK:
 *
 * <ul>
 *   <li><b>derive_shareable_key</b> -- {@code HMAC-SHA256("bitwarden-" + name, secret)} as
 *       the pseudo-random key, then HKDF-Expand to 64 bytes, which is
 *       {@code enc_key || mac_key}. The access token uses name {@code accesstoken} and
 *       info {@code sm-access-token}.</li>
 *   <li><b>EncString type 2</b> -- {@code 2.base64(iv)|base64(ct)|base64(mac)},
 *       AES-256-CBC with an HMAC-SHA256 tag over {@code iv || ct}.</li>
 * </ul>
 *
 * <p>{@link #selfTest()} checks the derivation against the SDK's own test vectors. It runs
 * at plugin start rather than only under a build, because the failure it guards against --
 * a JRE without a required algorithm, or a change of behaviour underneath us -- shows up
 * as a decryption that produces plausible-looking rubbish, and a wrong password is a far
 * worse thing to hand a channel than a clear error.
 */
public final class BitwardenCrypto {

    /** Encryption key and MAC key, in that order, as one 64-byte block. */
    public static final class SymmetricKey {
        final byte[] encryptionKey;
        final byte[] macKey;

        SymmetricKey(byte[] combined) {
            this.encryptionKey = Arrays.copyOfRange(combined, 0, 32);
            this.macKey = Arrays.copyOfRange(combined, 32, 64);
        }
    }

    private BitwardenCrypto() {
    }

    /**
     * Bitwarden's {@code derive_shareable_key}.
     *
     * @param secret the raw key material, 16 bytes for an access token
     * @param name   the domain separator, part of the HMAC key
     * @param info   the HKDF info parameter, or null for none
     */
    public static SymmetricKey deriveShareableKey(byte[] secret, String name, String info) {
        byte[] prk = hmac(("bitwarden-" + name).getBytes(StandardCharsets.UTF_8), secret);
        byte[] infoBytes = info == null ? new byte[0] : info.getBytes(StandardCharsets.UTF_8);
        return new SymmetricKey(hkdfExpand(prk, infoBytes, 64));
    }

    /** A 64-byte key that is already {@code enc_key || mac_key}, as the org key is. */
    public static SymmetricKey keyFromBytes(byte[] combined) {
        if (combined.length != 64) {
            throw new IllegalArgumentException(
                "expected a 64-byte key, got " + combined.length);
        }
        return new SymmetricKey(combined);
    }

    /**
     * Decrypts an EncString.
     *
     * <p>Only type 2 is handled. The other types are RSA, or AES without a MAC, and
     * neither appears in Secrets Manager -- accepting an unauthenticated type here would
     * mean decrypting something whose integrity nothing has checked.
     */
    public static String decrypt(String encString, SymmetricKey key)
            throws SecretProvider.VaultException {
        if (encString == null || encString.isBlank()) {
            throw new SecretProvider.VaultException("Bitwarden returned an empty value.");
        }
        int dot = encString.indexOf('.');
        if (dot < 0) {
            throw new SecretProvider.VaultException(
                "Bitwarden returned a value in an unrecognised format.");
        }
        String type = encString.substring(0, dot);
        if (!"2".equals(type)) {
            throw new SecretProvider.VaultException("Bitwarden returned an encrypted value "
                + "of type " + type + ", which this plugin does not support. Secrets "
                + "Manager values are expected to be type 2 (AES-256-CBC with HMAC).");
        }

        String[] parts = encString.substring(dot + 1).split("\\|");
        if (parts.length != 3) {
            throw new SecretProvider.VaultException(
                "Bitwarden returned a malformed encrypted value.");
        }

        byte[] iv;
        byte[] ciphertext;
        byte[] mac;
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            iv = decoder.decode(parts[0]);
            ciphertext = decoder.decode(parts[1]);
            mac = decoder.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new SecretProvider.VaultException(
                "Bitwarden returned an encrypted value that is not valid base64.", e);
        }

        // Verified before decrypting, and with a constant-time comparison. Decrypting
        // first and checking afterwards is the padding-oracle shape, and a byte-by-byte
        // comparison leaks where the first difference is.
        byte[] signed = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, signed, 0, iv.length);
        System.arraycopy(ciphertext, 0, signed, iv.length, ciphertext.length);
        if (!MessageDigest.isEqual(hmac(key.macKey, signed), mac)) {
            throw new SecretProvider.VaultException("A Bitwarden value failed its integrity "
                + "check. The access token does not match the data it was used on.");
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.encryptionKey, "AES"),
                new IvParameterSpec(iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecretProvider.VaultException(
                "A Bitwarden value could not be decrypted.", e);
        }
    }

    // ------------------------------------------------------------------
    // Primitives
    // ------------------------------------------------------------------

    /** HKDF-Expand from RFC 5869. Expand only: the PRK is already a pseudo-random key. */
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        byte[] output = new byte[length];
        byte[] block = new byte[0];
        int position = 0;
        for (int counter = 1; position < length; counter++) {
            byte[] input = new byte[block.length + info.length + 1];
            System.arraycopy(block, 0, input, 0, block.length);
            System.arraycopy(info, 0, input, block.length, info.length);
            input[input.length - 1] = (byte) counter;

            block = hmac(prk, input);
            int take = Math.min(block.length, length - position);
            System.arraycopy(block, 0, output, position, take);
            position += take;
        }
        return output;
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    // ------------------------------------------------------------------
    // Self test
    // ------------------------------------------------------------------

    /** The SDK's own vectors for {@code derive_shareable_key}. */
    private static final String[][] VECTORS = {
        {"&/$%F1a895g67HlX", "test_key", "",
         "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe"
         + "+ktR+U6qswxNnQ=="},
        {"67t9b5g67$%Dh89n", "test_key", "test",
         "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++"
         + "1LDW4iFD+infng=="},
    };

    /**
     * Checks the key derivation against Bitwarden's published vectors.
     *
     * @return null when everything matches, or a description of what did not
     */
    public static String selfTest() {
        try {
            for (String[] vector : VECTORS) {
                SymmetricKey key = deriveShareableKey(
                    vector[0].getBytes(StandardCharsets.UTF_8),
                    vector[1],
                    vector[2].isEmpty() ? null : vector[2]);
                byte[] combined = new byte[64];
                System.arraycopy(key.encryptionKey, 0, combined, 0, 32);
                System.arraycopy(key.macKey, 0, combined, 32, 32);
                String actual = Base64.getEncoder().encodeToString(combined);
                if (!vector[3].equals(actual)) {
                    return "derive_shareable_key(" + vector[1] + ") produced " + actual
                        + " rather than the published vector";
                }
            }
            return null;
        } catch (RuntimeException e) {
            return "key derivation is unavailable: " + e;
        }
    }
}
