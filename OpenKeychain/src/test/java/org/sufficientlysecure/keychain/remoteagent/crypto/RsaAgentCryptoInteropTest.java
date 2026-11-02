/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/** Standalone test run by tools/test-remote-rsa.py, with libgcrypt and GnuPG oracles. */
public final class RsaAgentCryptoInteropTest {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        byte[] message = "OpenKeychain prehashed agent signature test".getBytes(StandardCharsets.UTF_8);
        System.out.println("PUBLIC " + RsaAgentCrypto.hex(RsaAgentCrypto.publicKeySExpression(publicKey)));
        System.out.println("GRIP " + RsaAgentCrypto.keygrip(publicKey));
        System.out.println("MODULUS " + publicKey.getModulus().toString(16));
        System.out.println("EXPONENT " + publicKey.getPublicExponent().toString(16));
        for (int algorithm : new int[] {8, 9, 10}) {
            String digestName = algorithm == 8 ? "SHA-256" : algorithm == 9 ? "SHA-384" : "SHA-512";
            String signatureName = digestName.replace("-", "") + "withRSA";
            byte[] digest = MessageDigest.getInstance(digestName).digest(message);
            byte[] sexp = RsaAgentCrypto.signDigest(pair.getPrivate(), algorithm, digest, null);
            // The final atom is a fixed-size RSA signature, followed by three list terminators.
            byte[] signature = Arrays.copyOfRange(sexp, sexp.length - 3 - 256, sexp.length - 3);
            Signature verifier = Signature.getInstance(signatureName);
            verifier.initVerify(publicKey);
            verifier.update(message);
            if (!verifier.verify(signature)) {
                throw new AssertionError("Prehashed signature was not valid for the original message");
            }
            System.out.println("SIGNATURE " + algorithm + " " + RsaAgentCrypto.hex(digest)
                    + " " + RsaAgentCrypto.hex(sexp));
            expectRejected(() -> RsaAgentCrypto.signDigest(pair.getPrivate(), algorithm,
                    Arrays.copyOf(digest, digest.length - 1), null));
            expectRejected(() -> RsaAgentCrypto.signDigest(pair.getPrivate(), algorithm, null, null));
        }
        expectRejected(() -> RsaAgentCrypto.signDigest(pair.getPrivate(), 2, new byte[20], null));
        expectRejected(() -> RsaAgentCrypto.signDigest(pair.getPrivate(), 11, new byte[28], null));
    }

    private interface ThrowingAction { void run() throws Exception; }

    private static void expectRejected(ThrowingAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("Invalid digest accepted");
        } catch (GeneralSecurityException expected) {
            // Expected: reject before using the private key.
        }
    }
}
