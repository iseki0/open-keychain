/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/** GnuPG's RSA agent encoding. This class deliberately has no Android dependencies. */
public final class RsaAgentCrypto {
    private RsaAgentCrypto() {}

    public static String keygrip(RSAPublicKey key) throws GeneralSecurityException {
        // libgcrypt's RSA keygrip hashes the signed-positive MPI representation of n,
        // including its leading zero byte when its high bit is set (not an OpenPGP MPI).
        return hex(MessageDigest.getInstance("SHA-1").digest(key.getModulus().toByteArray()));
    }

    public static byte[] publicKeySExpression(RSAPublicKey key) {
        return list(atom("public-key"), list(atom("rsa"),
                list(atom("n"), atom(key.getModulus().toByteArray())),
                list(atom("e"), atom(key.getPublicExponent().toByteArray()))));
    }

    public static byte[] signDigest(PrivateKey key, int hashAlgorithm, byte[] digest,
            String provider) throws GeneralSecurityException {
        byte[] digestInfo = digestInfo(hashAlgorithm, digest);
        try {
            Signature signer = provider == null ? Signature.getInstance("NONEwithRSA")
                    : Signature.getInstance("NONEwithRSA", provider);
            signer.initSign(key);
            signer.update(digestInfo);
            // PKSIGN signs a supplied digest. SHA256withRSA here would hash it again.
            byte[] signature = signer.sign();
            return list(atom("sig-val"), list(atom("rsa"),
                    list(atom("s"), atom(signature))));
        } finally {
            Arrays.fill(digestInfo, (byte) 0);
        }
    }

    public static void validateDigest(int hashAlgorithm, byte[] digest)
            throws GeneralSecurityException {
        int length;
        switch (hashAlgorithm) {
            case 8: length = 32; break;
            case 9: length = 48; break;
            case 10: length = 64; break;
            default: throw new GeneralSecurityException("Unsupported digest algorithm");
        }
        if (digest == null || digest.length != length) {
            throw new GeneralSecurityException("Invalid digest length");
        }
    }

    private static byte[] digestInfo(int hashAlgorithm, byte[] digest)
            throws GeneralSecurityException {
        validateDigest(hashAlgorithm, digest);
        String prefix;
        switch (hashAlgorithm) {
            case 8: prefix = "3031300d060960864801650304020105000420"; break;
            case 9: prefix = "3041300d060960864801650304020205000430"; break;
            case 10: prefix = "3051300d060960864801650304020305000440"; break;
            default: throw new GeneralSecurityException("Unsupported digest algorithm");
        }
        byte[] result = new byte[prefix.length() / 2 + digest.length];
        for (int i = 0; i < prefix.length() / 2; i++) {
            result[i] = (byte) Integer.parseInt(prefix.substring(i * 2, i * 2 + 2), 16);
        }
        System.arraycopy(digest, 0, result, prefix.length() / 2, digest.length);
        return result;
    }

    public static String hex(byte[] bytes) {
        char[] digits = "0123456789ABCDEF".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = digits[(bytes[i] & 255) >>> 4];
            result[i * 2 + 1] = digits[bytes[i] & 15];
        }
        return new String(result);
    }

    private static byte[] atom(String text) {
        return atom(text.getBytes(StandardCharsets.US_ASCII));
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
        for (byte[] value : values) {
            out.write(value, 0, value.length);
        }
        out.write(')');
        return out.toByteArray();
    }
}
