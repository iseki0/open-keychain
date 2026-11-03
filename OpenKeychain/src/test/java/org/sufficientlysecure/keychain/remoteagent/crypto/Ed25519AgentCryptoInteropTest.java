/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/** Standalone test using only a disposable key provided by test-remote-ed25519.py. */
public final class Ed25519AgentCryptoInteropTest {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PGPSecretKey key = null;
        try (InputStream input = PGPUtil.getDecoderStream(Files.newInputStream(Path.of(args[0])))) {
            PGPSecretKeyRingCollection rings = new PGPSecretKeyRingCollection(input,
                    new JcaKeyFingerprintCalculator());
            Iterator<PGPSecretKeyRing> iterator = rings.getKeyRings();
            while (iterator.hasNext()) {
                Iterator<PGPSecretKey> keys = iterator.next().getSecretKeys();
                while (keys.hasNext()) {
                    PGPSecretKey candidate = keys.next();
                    if (RsaAgentCrypto.hex(candidate.getPublicKey().getFingerprint()).equals(args[1])) {
                        key = candidate;
                    }
                }
            }
        }
        if (key == null) throw new AssertionError("Missing test key");
        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider("BC");
        PublicKey publicKey = converter.getPublicKey(key.getPublicKey());
        PrivateKey privateKey = converter.getPrivateKey(key.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(new char[0])));
        System.out.println("PUBLIC " + RsaAgentCrypto.hex(Ed25519AgentCrypto.publicKeySExpression(publicKey)));
        System.out.println("GRIP " + Ed25519AgentCrypto.keygrip(publicKey));
        for (int algorithm : new int[] {8, 9, 10}) {
            String hash = algorithm == 8 ? "SHA-256" : algorithm == 9 ? "SHA-384" : "SHA-512";
            byte[] digest = MessageDigest.getInstance(hash).digest("GnuPG Ed25519 agent fixture".getBytes(StandardCharsets.UTF_8));
            byte[] signature = Ed25519AgentCrypto.signDigest(privateKey, algorithm, digest, "BC");
            System.out.println("SIGNATURE " + algorithm + " " + RsaAgentCrypto.hex(digest)
                    + " " + RsaAgentCrypto.hex(signature));
        }
        for (int unsupported : new int[] {0, 2, 11}) {
            try {
                Ed25519AgentCrypto.signDigest(privateKey, unsupported, new byte[32], "BC");
                throw new AssertionError("Unsupported digest accepted");
            } catch (GeneralSecurityException expected) {}
        }
        try {
            Ed25519AgentCrypto.signDigest(privateKey, 8, new byte[31], "BC");
            throw new AssertionError("Invalid digest accepted");
        } catch (GeneralSecurityException expected) {}
    }
}
