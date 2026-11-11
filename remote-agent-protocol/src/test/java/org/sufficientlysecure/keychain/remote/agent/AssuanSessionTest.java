package org.sufficientlysecure.keychain.remote.agent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class AssuanSessionTest {
    private static final String GRIP = "0123456789ABCDEF0123456789ABCDEF01234567";
    private static final String DIGEST = repeat("ab", 32);
    private static int checks;

    public static void main(String[] args) throws Exception {
        successAndOneShotDigest();
        rejectsUnsafeAndMalformedRequests();
        resetAndFailedSelectionDiscardState();
        binaryEscapingAndLimits();
        backendDenialConsumesRequest();
        System.out.println("AssuanSessionTest: " + checks + " checks passed");
    }

    private static void successAndOneShotDigest() throws Exception {
        FakeBackend backend = new FakeBackend();
        String listing = run(backend, "HAVEKEY --list=1000\nBYE\n");
        check(!listing.contains("ERR"), "GnuPG fast-path key listing accepted");
        String result = run(backend, "OPTION pinentry-mode=loopback\nGETINFO restricted\nHAVEKEY "
                + GRIP.toLowerCase() + "\nSIGKEY " + GRIP + "\nSETKEYDESC Remote+commit%0Asignature\n"
                + "SETHASH 8 " + DIGEST + "\nPKSIGN\nPKSIGN\nBYE\n");
        check(backend.signs == 1, "digest must only be signed once");
        check(backend.lastDescription.equals("Remote commit\nsignature"), "description decoding");
        check(backend.lastHash == 8, "hash is forwarded");
        check(backend.lastDigest.length == 32 && (backend.lastDigest[0] & 255) == 171,
                "digest is decoded without being rehashed");
        check(result.contains("D (7:sig-val(3:rsa(1:s1:x)))\nOK\n"), "canonical signature returned");
        check(result.contains("ERR 67108922"), "replay fails with no data");
    }

    private static void rejectsUnsafeAndMalformedRequests() throws Exception {
        FakeBackend backend = new FakeBackend();
        String result = run(backend, "PKDECRYPT\nEXPORT_KEY " + GRIP + "\nDELETE_KEY " + GRIP
                + "\nIMPORT_KEY\nGENKEY\nPASSWD\nOPTION unsafe=value\nSIGKEY " + GRIP
                + "\nSETHASH 2 " + repeat("ab", 20) + "\nPKSIGN\nSETHASH 8 aa\nPKSIGN\n"
                + "SETHASH 8 " + repeat("zz", 32) + "\nPKSIGN\nBYE\n");
        check(backend.signs == 0, "unsafe commands never reach backend");
        check(count(result, "Unsupported signing-agent command") == 6, "sensitive commands rejected");
        check(result.contains("Unsupported hash algorithm"), "SHA1 rejected");
        check(count(result, "Digest length or encoding") == 2, "digest shape validated");
        check(result.contains("Unknown option"), "unknown options not accepted");
    }

    private static void resetAndFailedSelectionDiscardState() throws Exception {
        FakeBackend backend = new FakeBackend();
        run(backend, "SIGKEY " + GRIP + "\nSETHASH 8 " + DIGEST
                + "\nRESET\nPKSIGN\nSIGKEY " + GRIP + "\nSETHASH 8 " + DIGEST
                + "\nSIGKEY invalid\nPKSIGN\nSIGKEY " + GRIP + "\nSETHASH 8 " + DIGEST
                + "\nSETHASH 8 bad\nPKSIGN\nBYE\n");
        check(backend.signs == 0, "invalid state transitions cannot reuse stale digest");
    }

    private static void binaryEscapingAndLimits() throws Exception {
        FakeBackend backend = new FakeBackend();
        backend.result = new byte[6000];
        for (int i = 0; i < backend.result.length; i++) {
            backend.result[i] = (byte) (i % 256);
        }
        byte[] result = runBytes(backend, ("SIGKEY " + GRIP + "\nSETHASH 8 " + DIGEST
                + "\nPKSIGN\nBYE\n").getBytes(StandardCharsets.US_ASCII));
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        int offset = 0;
        for (int i = 0; i < result.length; i++) {
            if (result[i] != '\n') { continue; }
            check(i - offset + 1 <= 1000, "every output line fits Assuan maximum");
            if (i - offset >= 2 && result[offset] == 'D' && result[offset + 1] == ' ') {
                for (int p = offset + 2; p < i; p++) {
                    if (result[p] == '%') {
                        decoded.write(Character.digit((char) result[++p], 16) * 16
                                + Character.digit((char) result[++p], 16));
                    } else { decoded.write(result[p]); }
                }
            }
            offset = i + 1;
        }
        check(Arrays.equals(decoded.toByteArray(), backend.result), "binary data round trips including percent/LF/CR/NUL");
        String tooLong = run(backend, repeat("x", 1001) + "\nNOP\n");
        check(tooLong.contains("Command exceeds"), "oversized command rejected");
        check(count(tooLong, "OK") == 1, "oversized connection is terminated");
        check(run(backend, "NOP").contains("Incomplete command"), "partial EOF is not executed");
        check(run(backend, "NOP\0\n").contains("Invalid command character"), "NUL injection rejected");
    }

    private static void backendDenialConsumesRequest() throws Exception {
        FakeBackend backend = new FakeBackend();
        backend.deny = true;
        String result = run(backend, "SIGKEY " + GRIP + "\nSETHASH 8 " + DIGEST
                + "\nPKSIGN\nPKSIGN\nBYE\n");
        check(backend.signs == 1, "denied requests cannot be replayed");
        check(result.contains("ERR 67108963"), "cancellation preserves gpg-error code");
    }

    private static String run(FakeBackend backend, String input) throws Exception {
        return new String(runBytes(backend, input.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    private static byte[] runBytes(FakeBackend backend, byte[] input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new AssuanSession(backend).serve(new ByteArrayInputStream(input), output);
        return output.toByteArray();
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) { result.append(value); }
        return result.toString();
    }

    private static int count(String value, String pattern) {
        int count = 0;
        int pos = 0;
        while ((pos = value.indexOf(pattern, pos)) >= 0) { count++; pos += pattern.length(); }
        return count;
    }

    private static void check(boolean value, String message) {
        checks++;
        if (!value) { throw new AssertionError(message); }
    }

    private static final class FakeBackend implements AgentBackend {
        int signs;
        int lastHash;
        byte[] lastDigest;
        String lastDescription;
        boolean deny;
        byte[] result = "(7:sig-val(3:rsa(1:s1:x)))".getBytes(StandardCharsets.US_ASCII);
        final AgentKey key = new AgentKey(GRIP,
                "(10:public-key(3:rsa(1:n1:x)(1:e3:\1\0\1)))".getBytes(StandardCharsets.US_ASCII), "1234");

        public List<AgentKey> getKeys() { return Collections.singletonList(key); }
        public byte[] sign(AgentKey key, int hash, byte[] digest, String description) throws AgentException {
            signs++;
            lastHash = hash;
            lastDigest = digest.clone();
            lastDescription = description;
            if (deny) { throw new AgentException(AgentException.CANCELED, "User denied signing"); }
            return result;
        }
    }
}
