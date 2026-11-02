/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

/** Public metadata for one supported signing key; contains no private-key material. */
public final class RemoteSigningKey {
    public final long masterKeyId;
    public final long subKeyId;
    public final String fingerprint;
    public final String keygrip;
    public final byte[] publicKeySExpression;
    public final String userId;

    RemoteSigningKey(long masterKeyId, long subKeyId, String fingerprint, String keygrip,
            byte[] publicKeySExpression, String userId) {
        this.masterKeyId = masterKeyId;
        this.subKeyId = subKeyId;
        this.fingerprint = fingerprint;
        this.keygrip = keygrip;
        this.publicKeySExpression = publicKeySExpression.clone();
        this.userId = userId;
    }
}
