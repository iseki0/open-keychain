/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

/** Completes gpg-bridge's full-message signature using an already initialized signer. */
public final class BridgePgpSigning {
    public static final int MAX_DATA = 1024 * 1024;

    private BridgePgpSigning() {}

    public static void validateData(byte[] data) throws PGPException {
        if (data == null || data.length == 0 || data.length > MAX_DATA) {
            throw new PGPException("Bridge data must contain between 1 byte and 1 MiB");
        }
    }

    public static BridgeSignature complete(PGPSignatureGenerator generator, PGPPublicKey publicKey,
            byte[] data) throws PGPException, IOException {
        validateData(data);
        // The OpenPGP generator hashes data and its signature trailer exactly once.
        generator.update(data);
        PGPSignature result = generator.generate();
        if (result.getKeyID() != publicKey.getKeyID()
                || result.getSignatureType() != PGPSignature.BINARY_DOCUMENT
                || result.getHashAlgorithm() != HashAlgorithmTags.SHA256) {
            throw new PGPException("Unexpected bridge signing identity or signature format");
        }
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (ArmoredOutputStream armor = new ArmoredOutputStream(encoded)) {
            result.encode(armor);
        }
        String fingerprint = RsaAgentCrypto.hex(publicKey.getFingerprint());
        String status = String.format(Locale.ROOT, "[GNUPG:] SIG_CREATED D %d %d %02x %d %s\n",
                result.getKeyAlgorithm(), result.getHashAlgorithm(), result.getSignatureType(),
                result.getCreationTime().getTime() / 1000L, fingerprint);
        return new BridgeSignature(new String(encoded.toByteArray(), StandardCharsets.US_ASCII), status);
    }
}
