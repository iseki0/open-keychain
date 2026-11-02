/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import android.content.Context;
import androidx.annotation.WorkerThread;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.util.Passphrase;

/** Local software RSA signing keys for the explicitly selected remote-agent identities. */
@WorkerThread
public final class RemoteSigningRepository {
    private final KeyRepository repository;

    public RemoteSigningRepository(Context context) {
        repository = KeyRepository.create(context);
    }

    /** For local selection UI only. Call listKeys with the saved selection for network requests. */
    public List<RemoteSigningKey> listAvailableKeys()
            throws NotFoundException, PgpGeneralException, GeneralSecurityException {
        List<RemoteSigningKey> result = new ArrayList<>();
        for (UnifiedKeyInfo info : repository.getAllUnifiedKeyInfoWithSecret()) {
            CanonicalizedSecretKeyRing ring = repository.getCanonicalizedSecretKeyRing(info.master_key_id());
            if (!validRing(ring)) {
                continue;
            }
            for (CanonicalizedSecretKey key : ring.secretKeyIterator()) {
                if (supported(key)) {
                    result.add(describe(ring, key));
                }
            }
        }
        return Collections.unmodifiableList(result);
    }

    /** Empty selections expose no keys. Selection is by exact subkey fingerprint. */
    public List<RemoteSigningKey> listKeys(Set<String> allowedFingerprints)
            throws NotFoundException, PgpGeneralException, GeneralSecurityException {
        if (allowedFingerprints == null || allowedFingerprints.isEmpty()) {
            return Collections.emptyList();
        }
        List<RemoteSigningKey> result = new ArrayList<>();
        for (RemoteSigningKey key : listAvailableKeys()) {
            if (allowedFingerprints.contains(key.fingerprint)) {
                result.add(key);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Consumes and wipes passphrase on every path. The caller must first obtain approval
     * for this exact key and digest and recheck its saved key/peer allowlists.
     */
    public byte[] sign(RemoteSigningKey selected, int hashAlgorithm, byte[] digest,
            char[] passphrase) throws NotFoundException, PgpGeneralException,
            GeneralSecurityException {
        Passphrase localPassphrase = null;
        byte[] localDigest = null;
        try {
            if (selected == null || passphrase == null) {
                throw new GeneralSecurityException("Missing local approval or selected key");
            }
            RsaAgentCrypto.validateDigest(hashAlgorithm, digest);
            localDigest = digest.clone();
            CanonicalizedSecretKeyRing ring = repository.getCanonicalizedSecretKeyRing(selected.masterKeyId);
            if (!validRing(ring)) {
                throw new GeneralSecurityException("Signing keyring is no longer valid");
            }
            CanonicalizedSecretKey key = null;
            for (CanonicalizedSecretKey candidate : ring.secretKeyIterator()) {
                if (candidate.getKeyId() == selected.subKeyId) {
                    key = candidate;
                    break;
                }
            }
            if (key == null || !supported(key)) {
                throw new GeneralSecurityException("Signing key is unavailable or unsupported");
            }
            RemoteSigningKey current = describe(ring, key);
            if (!current.fingerprint.equals(selected.fingerprint)
                    || !current.keygrip.equals(selected.keygrip)) {
                throw new GeneralSecurityException("Signing key changed");
            }
            localPassphrase = new Passphrase(passphrase);
            if (!key.unlock(localPassphrase)) {
                throw new GeneralSecurityException("Incorrect passphrase");
            }
            return key.signRsaDigest(hashAlgorithm, localDigest);
        } finally {
            if (localPassphrase != null) {
                localPassphrase.removeFromMemory();
            }
            if (passphrase != null) {
                Arrays.fill(passphrase, '\0');
            }
            if (localDigest != null) {
                Arrays.fill(localDigest, (byte) 0);
            }
        }
    }

    private boolean supported(CanonicalizedSecretKey key) throws NotFoundException {
        if (key.getAlgorithm() != PublicKeyAlgorithmTags.RSA_GENERAL
                && key.getAlgorithm() != PublicKeyAlgorithmTags.RSA_SIGN) {
            return false;
        }
        if (!key.canSign() || !key.isValid()
                || key.getCreationTime().after(new Date()) || key.getBitStrength() < 2048) {
            return false;
        }
        SecretKeyType type = repository.getSecretKeyType(key.getKeyId());
        return type == SecretKeyType.PASSPHRASE || type == SecretKeyType.PASSPHRASE_EMPTY;
    }

    private static boolean validRing(CanonicalizedSecretKeyRing ring) {
        return ring.getPublicKey().isValid()
                && !ring.getPublicKey().getCreationTime().after(new Date());
    }

    private static RemoteSigningKey describe(CanonicalizedSecretKeyRing ring,
            CanonicalizedSecretKey key) throws PgpGeneralException, GeneralSecurityException {
        PublicKey publicKey = key.getJcaPublicKey();
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new GeneralSecurityException("Unsupported public key");
        }
        RSAPublicKey rsa = (RSAPublicKey) publicKey;
        return new RemoteSigningKey(ring.getMasterKeyId(), key.getKeyId(),
                RsaAgentCrypto.hex(key.getFingerprint()), RsaAgentCrypto.keygrip(rsa),
                RsaAgentCrypto.publicKeySExpression(rsa), ring.getPrimaryUserIdWithFallback());
    }
}
