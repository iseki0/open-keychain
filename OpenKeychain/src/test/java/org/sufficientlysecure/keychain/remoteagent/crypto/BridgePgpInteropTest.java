/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/** Standalone fixture; tools/test-gpg-bridge-pgp.py creates every key in a disposable home. */
public final class BridgePgpInteropTest {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PGPSecretKey selected = null;
        try (InputStream input = PGPUtil.getDecoderStream(Files.newInputStream(Path.of(args[0])))) {
            PGPSecretKeyRingCollection rings = new PGPSecretKeyRingCollection(input,
                    new JcaKeyFingerprintCalculator());
            Iterator<PGPSecretKeyRing> ringIterator = rings.getKeyRings();
            while (ringIterator.hasNext()) {
                Iterator<PGPSecretKey> keys = ringIterator.next().getSecretKeys();
                while (keys.hasNext()) {
                    PGPSecretKey candidate = keys.next();
                    if (RsaAgentCrypto.hex(candidate.getPublicKey().getFingerprint()).equals(args[3])) {
                        selected = candidate;
                    }
                }
            }
        }
        if (selected == null || selected.getPublicKey().isMasterKey()) {
            throw new AssertionError("Expected the exact selected signing subkey");
        }
        char[] password = "temporary bridge fixture".toCharArray();
        PGPPrivateKey privateKey;
        try {
            privateKey = selected.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                    .setProvider("BC").build(password));
        } finally {
            Arrays.fill(password, '\0');
        }
        byte[] data = Files.readAllBytes(Path.of(args[1]));
        PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                selected.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider("BC"));
        generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        PGPSignatureSubpacketGenerator packets = new PGPSignatureSubpacketGenerator();
        packets.setSignerUserID(false, "Bridge fixture <bridge@example.invalid>");
        packets.setSignatureCreationTime(false, new Date());
        generator.setHashedSubpackets(packets.generate());
        BridgeSignature signed = BridgePgpSigning.complete(generator, selected.getPublicKey(), data);
        Files.write(Path.of(args[2] + ".asc"), signed.signature.getBytes(StandardCharsets.US_ASCII));
        Files.write(Path.of(args[2] + ".status"), signed.status.getBytes(StandardCharsets.US_ASCII));
        if (!signed.signature.startsWith("-----BEGIN PGP SIGNATURE-----")
                || !signed.status.matches("\\[GNUPG:\\] SIG_CREATED D "
                        + selected.getPublicKey().getAlgorithm() + " 8 00 [0-9]+ " + args[3] + "\\n")) {
            throw new AssertionError("Signature/status identity mismatch");
        }
        for (byte[] invalid : new byte[][] {null, new byte[0], new byte[BridgePgpSigning.MAX_DATA + 1]}) {
            try {
                BridgePgpSigning.validateData(invalid);
                throw new AssertionError("Invalid data length accepted");
            } catch (PGPException expected) {}
        }
        BridgePgpSigning.validateData(new byte[BridgePgpSigning.MAX_DATA]);
    }
}
