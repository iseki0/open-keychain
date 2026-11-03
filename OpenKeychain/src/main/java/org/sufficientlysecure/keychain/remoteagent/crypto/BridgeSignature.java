/* SPDX-License-Identifier: GPL-3.0-or-later */
package org.sufficientlysecure.keychain.remoteagent.crypto;

/** An armored detached OpenPGP signature and its matching GnuPG status line. */
public final class BridgeSignature {
    public final String signature;
    public final String status;

    BridgeSignature(String signature, String status) {
        this.signature = signature;
        this.status = status;
    }
}
