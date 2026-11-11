/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/** GnuPG agent encoding for legacy OpenPGP Ed25519 software keys. */
public final class Ed25519AgentCrypto {
    // libgcrypt's normalized Ed25519 domain parameters (unsigned absolute MPIs).
    // Keygrips hash pabgnq, not the public-key S-expression itself. SHA-1 is only
    // the GnuPG key identifier here; signatures use Ed25519 and SHA-2 digests.
    private static final byte[][] DOMAIN = {
            fromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
            fromHex("01"),
            fromHex("2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A"),
            fromHex("04216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
                    + "6666666666666666666666666666666666666666666666666666666666666658"),
            fromHex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
    };

    private Ed25519AgentCrypto() {}

    public static String keygrip(PublicKey key) throws GeneralSecurityException {
        byte[] point = point(key);
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        char[] names = "pabgnq".toCharArray();
        for (int i = 0; i < names.length; i++) {
            byte[] value = i == DOMAIN.length ? point : DOMAIN[i];
            digest.update(("(1:" + names[i] + value.length + ":").getBytes(StandardCharsets.US_ASCII));
            digest.update(value);
            digest.update((byte) ')');
        }
        return RsaAgentCrypto.hex(digest.digest());
    }

    public static byte[] publicKeySExpression(PublicKey key) throws GeneralSecurityException {
        byte[] compact = point(key);
        byte[] encodedPoint = new byte[33];
        encodedPoint[0] = 0x40;
        System.arraycopy(compact, 0, encodedPoint, 1, compact.length);
        return list(atom("public-key"), list(atom("ecc"),
                list(atom("curve"), atom("Ed25519")),
                list(atom("flags"), atom("eddsa")),
                list(atom("q"), atom(encodedPoint))));
    }

    public static byte[] signDigest(PrivateKey key, int hashAlgorithm, byte[] digest,
            String provider) throws GeneralSecurityException {
        RsaAgentCrypto.validateDigest(hashAlgorithm, digest);
        // GnuPG PKSIGN supplies the OpenPGP digest. Pure Ed25519 signs that exact
        // byte string; SHA256with... or Ed25519ph would change its semantics.
        Signature signer = provider == null ? Signature.getInstance("Ed25519")
                : Signature.getInstance("Ed25519", provider);
        signer.initSign(key);
        signer.update(digest);
        byte[] signature = signer.sign();
        if (signature.length != 64) {
            throw new GeneralSecurityException("Unexpected Ed25519 signature length");
        }
        return list(atom("sig-val"), list(atom("eddsa"),
                list(atom("r"), atom(Arrays.copyOfRange(signature, 0, 32))),
                list(atom("s"), atom(Arrays.copyOfRange(signature, 32, 64)))));
    }

    private static byte[] point(PublicKey key) throws GeneralSecurityException {
        try {
            if (key == null || key.getEncoded() == null) {
                throw new GeneralSecurityException("Missing Ed25519 public key");
            }
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(key.getEncoded());
            byte[] value = info.getPublicKeyData().getOctets();
            if (!EdECObjectIdentifiers.id_Ed25519.equals(info.getAlgorithm().getAlgorithm())
                    || value.length != 32) {
                throw new GeneralSecurityException("Expected an Ed25519 public key");
            }
            return value;
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new GeneralSecurityException("Invalid Ed25519 public key", e);
        }
    }

    private static byte[] fromHex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static byte[] atom(String value) {
        return atom(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] atom(byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] length = (value.length + ":").getBytes(StandardCharsets.US_ASCII);
        out.write(length, 0, length.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static byte[] list(byte[]... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('(');
        for (byte[] value : values) out.write(value, 0, value.length);
        out.write(')');
        return out.toByteArray();
    }
}
