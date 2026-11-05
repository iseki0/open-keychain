package org.sufficientlysecure.keychain.remoteagent;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** Connection-scoped, phone-only prefill. Signing always consumes a separate copy. */
final class SigningPassphraseCache {
    private final Map<String, char[]> values = new HashMap<>();

    /** Consumes the supplied array even when replacing or removing a value. */
    synchronized void put(String fingerprint, char[] passphrase) {
        try {
            char[] previous = values.remove(fingerprint);
            if (previous != null) Arrays.fill(previous, '\0');
            if (passphrase.length > 0) values.put(fingerprint, passphrase.clone());
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    synchronized char[] copy(String fingerprint) {
        char[] value = values.get(fingerprint);
        return value == null ? null : value.clone();
    }

    synchronized boolean contains(String fingerprint) {
        return values.containsKey(fingerprint);
    }

    synchronized void clear() {
        for (char[] value : values.values()) Arrays.fill(value, '\0');
        values.clear();
    }
}
