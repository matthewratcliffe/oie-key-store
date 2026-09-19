/*
 * SPDX-License-Identifier: MPL-2.0
 */
package org.openintegrationengine.plugins.keystore.provider;

import org.openintegrationengine.plugins.keystore.VaultConnection;

import java.util.List;

/**
 * What a vault has to be able to do for this plugin.
 *
 * <p>Deliberately three methods and no lifecycle. Everything a provider needs comes from
 * the {@link VaultConnection} it is handed, so providers hold no per-connection state of
 * their own except a token cache -- which means editing a connection in the console takes
 * effect on the next fetch without anything having to be torn down and rebuilt.
 */
public interface SecretProvider {

    /** The value fetched from a vault, plus what the vault said about it. */
    final class Secret {
        /** The payload exactly as stored. May itself be a JSON document. */
        public final String value;
        /** The version actually returned, when the vault reports one. */
        public final String version;

        public Secret(String value, String version) {
            this.value = value;
            this.version = version == null ? "" : version;
        }
    }

    /**
     * Raised when the vault answered, but not with a secret.
     *
     * <p>Separate from an {@link java.io.IOException} because the two are acted on
     * differently: a network fault is worth retrying on the next pass and is usually not
     * the operator's doing, whereas "no such secret" or "access denied" will say exactly
     * the same thing in five minutes and belongs in front of a human now.
     */
    class VaultException extends Exception {
        private static final long serialVersionUID = 1L;

        public VaultException(String message) {
            super(message);
        }

        public VaultException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Which connection type this provider serves. */
    VaultConnection.Type type();

    /**
     * Fetches one secret.
     *
     * @param connection the vault, with its credential fields already decrypted
     * @param secretId   the secret's name in Azure, or its name or full ARN in AWS
     * @param version    a specific version, or empty for the current one
     */
    Secret fetch(VaultConnection connection, String secretId, String version)
        throws VaultException;

    /**
     * Proves the connection works, and reports what it could see.
     *
     * <p>Returns lines for the console rather than a bare boolean. "Authenticated, but
     * this identity cannot list secrets" is the single most common half-working state --
     * the app registration exists and the credential is right, and someone forgot the
     * access policy -- and a red cross saying "failed" sends people back to re-check the
     * client secret they got right the first time.
     */
    List<String> test(VaultConnection connection) throws VaultException;
}
