/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

/** Public metadata for one supported signing key; contains no private-key material. */
public final class RemoteSigningKey {
    public final long masterKeyId;
    public final long subKeyId;
    public final String fingerprint;
    /** Null when the key is available through gpg-bridge but not the Assuan subset. */
    public final String keygrip;
    public final byte[] publicKeySExpression;
    public final String userId;
    public final String primaryFingerprint;
    public final String algorithmName;
    /** Earliest primary/signing-key expiry in epoch seconds, or zero for no expiry. */
    public final long expires;

    RemoteSigningKey(long masterKeyId, long subKeyId, String fingerprint, String keygrip,
            byte[] publicKeySExpression, String userId, String primaryFingerprint, long expires,
            String algorithmName) {
        this.masterKeyId = masterKeyId;
        this.subKeyId = subKeyId;
        this.fingerprint = fingerprint;
        this.keygrip = keygrip;
        this.publicKeySExpression = publicKeySExpression == null ? null : publicKeySExpression.clone();
        this.userId = userId;
        this.primaryFingerprint = primaryFingerprint;
        this.expires = expires;
        this.algorithmName = algorithmName;
    }
}
