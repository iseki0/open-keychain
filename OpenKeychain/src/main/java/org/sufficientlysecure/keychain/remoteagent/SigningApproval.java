package org.sufficientlysecure.keychain.remoteagent;

import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;

/** In-memory capability for one local approval; nothing sensitive is placed in an Intent. */
final class SigningApproval {
    final String id = UUID.randomUUID().toString();
    final String peer;
    final RemoteSigningKey key;
    final int hashAlgorithm;
    final byte[] digest;
    final CompletableFuture<char[]> answer = new CompletableFuture<>();
    private final AtomicBoolean claimed = new AtomicBoolean();

    SigningApproval(String peer, RemoteSigningKey key, int hashAlgorithm, byte[] digest) {
        this.peer = peer;
        this.key = key;
        this.hashAlgorithm = hashAlgorithm;
        this.digest = digest.clone();
    }

    void approve(char[] password) {
        if (!answer.complete(password)) Arrays.fill(password, '\0');
    }

    boolean claim() {
        return !answer.isDone() && claimed.compareAndSet(false, true);
    }

    void deny() {
        if (!answer.complete(null)) {
            char[] password = answer.getNow(null);
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    String digestHex() {
        StringBuilder result = new StringBuilder();
        for (byte value : digest) result.append(String.format(java.util.Locale.ROOT, "%02X", value & 255));
        return result.toString();
    }

    String hashName() {
        switch (hashAlgorithm) {
            case 8: return "SHA-256";
            case 9: return "SHA-384";
            case 10: return "SHA-512";
            default: return "Unsupported";
        }
    }
}
