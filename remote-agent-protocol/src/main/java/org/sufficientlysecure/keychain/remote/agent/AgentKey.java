package org.sufficientlysecure.keychain.remote.agent;

import java.util.Locale;

/** Public metadata for one explicitly shared signing key. */
public final class AgentKey {
    private final String keygrip;
    private final byte[] publicKeySExpression;
    private final String keyId;

    public AgentKey(String keygrip, byte[] publicKeySExpression, String keyId) {
        if (keygrip == null || !keygrip.matches("[a-fA-F0-9]{40}")) {
            throw new IllegalArgumentException("A keygrip must contain 40 hexadecimal characters");
        }
        if (publicKeySExpression == null || publicKeySExpression.length == 0) {
            throw new IllegalArgumentException("A public-key S-expression is required");
        }
        this.keygrip = keygrip.toUpperCase(Locale.ROOT);
        this.publicKeySExpression = publicKeySExpression.clone();
        this.keyId = keyId;
    }

    public String getKeygrip() { return keygrip; }
    public byte[] getPublicKeySExpression() { return publicKeySExpression.clone(); }
    public String getKeyId() { return keyId; }
}
