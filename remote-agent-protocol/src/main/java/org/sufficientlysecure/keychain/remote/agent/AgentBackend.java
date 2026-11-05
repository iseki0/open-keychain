package org.sufficientlysecure.keychain.remote.agent;

import java.util.List;

/** All private-key access and user approval remain behind this boundary. */
public interface AgentBackend {
    List<AgentKey> getKeys() throws AgentException;

    /**
     * Sign the supplied digest, without hashing it again, and return a canonical
     * libgcrypt (sig-val ...) S-expression. The description is untrusted peer text.
     * Implementations must authorize this individual operation locally.
     */
    byte[] sign(AgentKey key, int hashAlgorithm, byte[] digest, String description)
            throws AgentException;
}
