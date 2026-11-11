/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

import android.content.Context;
import androidx.annotation.WorkerThread;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKey;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKeyRing;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKey.SecretKeyType;
import org.sufficientlysecure.keychain.pgp.CanonicalizedSecretKeyRing;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.util.Passphrase;

/** Valid local software signing keys for explicitly selected remote signing identities. */
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

    /** Public-only gpg-bridge metadata for the exact locally selected signing keys. */
    public String bridgeKeysJson(Set<String> allowedFingerprints)
            throws NotFoundException, PgpGeneralException, GeneralSecurityException,
            IOException, JSONException {
        List<RemoteSigningKey> keys = listKeys(allowedFingerprints);
        JSONArray metadata = new JSONArray();
        Set<Long> masters = new LinkedHashSet<>();
        for (RemoteSigningKey key : keys) {
            metadata.put(new JSONObject().put("primary", key.primaryFingerprint)
                    .put("fingerprint", key.fingerprint).put("uid", key.userId)
                    .put("expires", key.expires).put("hardware", false));
            masters.add(key.masterKeyId);
        }
        StringBuilder publicKeys = new StringBuilder();
        for (long master : masters) {
            publicKeys.append(repository.getPublicKeyRingAsArmoredString(master));
            if (publicKeys.length() > BridgePgpSigning.MAX_DATA) {
                throw new GeneralSecurityException("Selected public keys exceed the bridge limit");
            }
        }
        return new JSONObject().put("keys", metadata).put("public_keys", publicKeys.toString()).toString();
    }

    /** Checks a passphrase by unlocking the selected subkey locally. Always wipes passphrase. */
    public boolean checkPassphrase(RemoteSigningKey selected, char[] passphrase)
            throws NotFoundException, PgpGeneralException, GeneralSecurityException {
        Passphrase localPassphrase = new Passphrase(passphrase);
        try {
            CanonicalizedSecretKeyRing ring = repository.getCanonicalizedSecretKeyRing(selected.masterKeyId);
            for (CanonicalizedSecretKey candidate : ring.secretKeyIterator()) {
                if (candidate.getKeyId() == selected.subKeyId) {
                    if (!supported(candidate)) throw new GeneralSecurityException("Signing key is unsupported");
                    return candidate.unlock(localPassphrase);
                }
            }
            throw new GeneralSecurityException("Signing key is unavailable");
        } finally {
            localPassphrase.removeFromMemory();
        }
    }

    /** True when the selected subkey's secret material is stored without a passphrase. */
    public boolean hasEmptyPassphrase(RemoteSigningKey selected) throws NotFoundException {
        return repository.getSecretKeyType(selected.subKeyId) == SecretKeyType.PASSPHRASE_EMPTY;
    }

    /**
     * Signs the exact raw gpg-bridge message after local approval. Consumes and wipes
     * passphrase. The caller must enforce its current fingerprint and peer allowlists.
     */
    public BridgeSignature signData(RemoteSigningKey selected, byte[] data, char[] passphrase)
            throws NotFoundException, PgpGeneralException, GeneralSecurityException {
        Passphrase localPassphrase = null;
        byte[] localData = null;
        try {
            if (selected == null || passphrase == null) {
                throw new GeneralSecurityException("Missing local approval or selected key");
            }
            if (data == null || data.length == 0 || data.length > BridgePgpSigning.MAX_DATA) {
                throw new GeneralSecurityException("Invalid bridge message length");
            }
            localData = data.clone();
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
                    || !Objects.equals(current.keygrip, selected.keygrip)) {
                throw new GeneralSecurityException("Signing key changed");
            }
            localPassphrase = new Passphrase(passphrase);
            if (!key.unlock(localPassphrase)) {
                throw new GeneralSecurityException("Incorrect passphrase");
            }
            return key.signBridgeData(localData);
        } finally {
            if (localPassphrase != null) localPassphrase.removeFromMemory();
            if (passphrase != null) Arrays.fill(passphrase, '\0');
            if (localData != null) Arrays.fill(localData, (byte) 0);
        }
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
                    || !Objects.equals(current.keygrip, selected.keygrip)) {
                throw new GeneralSecurityException("Signing key changed");
            }
            if (current.keygrip == null || current.publicKeySExpression == null) {
                throw new GeneralSecurityException("This signing key requires the gpg-bridge protocol");
            }
            localPassphrase = new Passphrase(passphrase);
            if (!key.unlock(localPassphrase)) {
                throw new GeneralSecurityException("Incorrect passphrase");
            }
            return key.getAlgorithm() == PublicKeyAlgorithmTags.EDDSA
                    ? key.signEd25519Digest(hashAlgorithm, localDigest)
                    : key.signRsaDigest(hashAlgorithm, localDigest);
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
        if (!supportedAlgorithm(key) || !key.canSign() || !key.isValid()
                || key.getCreationTime().after(new Date())) {
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
        String grip = null;
        byte[] expression = null;
        try {
            if (key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL
                    || key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN) {
                PublicKey publicKey = key.getJcaPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    grip = RsaAgentCrypto.keygrip((RSAPublicKey) publicKey);
                    expression = RsaAgentCrypto.publicKeySExpression((RSAPublicKey) publicKey);
                }
            } else if (isEd25519(key)) {
                PublicKey publicKey = key.getJcaPublicKey();
                grip = Ed25519AgentCrypto.keygrip(publicKey);
                expression = Ed25519AgentCrypto.publicKeySExpression(publicKey);
            }
        } catch (PgpGeneralException | GeneralSecurityException unavailableAssuanMetadata) {
            // gpg-bridge signs a full OpenPGP message and does not need an Assuan
            // keygrip. Preserve the key in the local picker if this optional encoding fails.
            grip = null;
            expression = null;
        }
        return new RemoteSigningKey(ring.getMasterKeyId(), key.getKeyId(),
                RsaAgentCrypto.hex(key.getFingerprint()), grip,
                expression, ring.getPrimaryUserIdWithFallback(),
                RsaAgentCrypto.hex(ring.getPublicKey().getFingerprint()),
                earliestExpiry(ring.getPublicKey().getExpiryTime(), key.getExpiryTime()), algorithmName(key));
    }

    private static boolean isEd25519(CanonicalizedPublicKey key) {
        if (key.getAlgorithm() != PublicKeyAlgorithmTags.EDDSA) return false;
        String curve = key.getCurveOid();
        return "1.3.6.1.4.1.11591.15.1".equals(curve) || "1.3.101.112".equals(curve);
    }

    private static boolean supportedAlgorithm(CanonicalizedPublicKey key) {
        switch (key.getAlgorithm()) {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            case PublicKeyAlgorithmTags.DSA:
            case PublicKeyAlgorithmTags.ECDSA:
                return true;
            case PublicKeyAlgorithmTags.EDDSA:
                return isEd25519(key);
            default:
                return false;
        }
    }

    /** Local technical diagnostics only; never called from a network request. */
    public List<String> diagnosticInventory() {
        List<String> result = new ArrayList<>();
        for (UnifiedKeyInfo info : repository.getAllUnifiedKeyInfo()) {
            try {
                CanonicalizedPublicKeyRing ring = repository.getCanonicalizedPublicKeyRing(info.master_key_id());
                CanonicalizedPublicKey primary = ring.getPublicKey();
                boolean primaryValid = primary.isValid() && !primary.getCreationTime().after(new Date());
                result.add("identity=" + RsaAgentCrypto.hex(primary.getFingerprint())
                        + " has_secret=" + info.has_any_secret() + " valid=" + primaryValid);
                for (CanonicalizedPublicKey key : ring.publicKeyIterator()) {
                    SecretKeyType type;
                    try { type = repository.getSecretKeyType(key.getKeyId()); }
                    catch (NotFoundException missing) { type = SecretKeyType.UNAVAILABLE; }
                    String reason = diagnosticReason(key, type, primaryValid);
                    boolean available = "available".equals(reason);
                    String assuan = available ? assuanMetadataStatus(key) : "unavailable";
                    result.add("key=" + RsaAgentCrypto.hex(key.getFingerprint())
                            + " algorithm=" + algorithmName(key) + "(" + key.getAlgorithm() + ")"
                            + " curve=" + key.getCurveOid() + " can_sign=" + key.canSign()
                            + " valid=" + key.isValid() + " secret_type=" + type
                            + " gpg_bridge=" + available + " assuan=" + assuan
                            + " reason=" + reason);
                }
            } catch (Exception failure) {
                result.add("identity_id=" + Long.toHexString(info.master_key_id())
                        + " inventory_error=" + failure.getClass().getSimpleName());
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static String diagnosticReason(CanonicalizedPublicKey key, SecretKeyType type,
            boolean primaryValid) {
        if (!primaryValid) return "primary_key_invalid_or_not_yet_valid";
        if (!key.canSign()) return "not_signing_capable";
        if (!key.isValid() || key.getCreationTime().after(new Date())) return "key_invalid_or_not_yet_valid";
        if (type == SecretKeyType.DIVERT_TO_CARD) return "hardware_token_ui_not_integrated";
        if (type != SecretKeyType.PASSPHRASE && type != SecretKeyType.PASSPHRASE_EMPTY)
            return "local_software_private_key_unavailable";
        if (!supportedAlgorithm(key)) return "unsupported_openpgp_signing_algorithm_or_curve";
        return "available";
    }

    private static String assuanMetadataStatus(CanonicalizedPublicKey key) {
        try {
            if (key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL
                    || key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN) {
                RSAPublicKey publicKey = (RSAPublicKey) key.getJcaPublicKey();
                RsaAgentCrypto.keygrip(publicKey);
                RsaAgentCrypto.publicKeySExpression(publicKey);
                return "available";
            }
            if (isEd25519(key)) {
                PublicKey publicKey = key.getJcaPublicKey();
                Ed25519AgentCrypto.keygrip(publicKey);
                Ed25519AgentCrypto.publicKeySExpression(publicKey);
                return "available";
            }
            return "gpg_bridge_only";
        } catch (Exception failure) {
            return "metadata_error_" + failure.getClass().getSimpleName();
        }
    }

    private static String algorithmName(CanonicalizedPublicKey key) {
        switch (key.getAlgorithm()) {
            case PublicKeyAlgorithmTags.RSA_GENERAL: return "RSA";
            case PublicKeyAlgorithmTags.RSA_SIGN: return "RSA_SIGN";
            case PublicKeyAlgorithmTags.DSA: return "DSA";
            case PublicKeyAlgorithmTags.ECDSA: return "ECDSA";
            case PublicKeyAlgorithmTags.EDDSA: return isEd25519(key) ? "Ed25519" : "EdDSA";
            default: return "OTHER";
        }
    }

    private static long earliestExpiry(Date primary, Date signing) {
        if (primary == null) return signing == null ? 0 : signing.getTime() / 1000L;
        if (signing == null) return primary.getTime() / 1000L;
        return Math.min(primary.getTime(), signing.getTime()) / 1000L;
    }
}
