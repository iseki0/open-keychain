package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

public class RemoteAgentDiagnosticBufferTest {
    @Test public void redactsPairingTicketsAndTailscaleKeys() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "Pairing gpgbridge:v1:AbCdEf0123456789_- failed; auth tskey-auth-fakePrivateCredential");
        assertFalse(value.contains("AbCdEf0123456789_-"));
        assertFalse(value.contains("fakePrivateCredential"));
        assertTrue(value.contains("failed"));
    }

    @Test public void redactsCredentialAssignmentsAndJsonValues() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "password='fake password with spaces'\nkey=fakeKeyMaterial\n"
                + "{\"psk\":\"fakePskMaterial\",\"token\":\"fakeAccessToken\","
                + "\"AuthURL\":\"https://login.tailscale.com/a/fakeAuthPath\"}");
        for (String secret : new String[] {"fake password with spaces", "fakeKeyMaterial",
                "fakePskMaterial", "fakeAccessToken", "fakeAuthPath"}) {
            assertFalse("Leaked " + secret, value.contains(secret));
        }
    }

    @Test public void redactsAuthorizationHeadersAndSchemes() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "Authorization: Bearer fakeBearerCredential\n"
                + "Proxy-Authorization: Basic ZmFrZTpzZWNyZXQ=\n"
                + "{\"Authorization\":\"Bearer fakeJsonBearer\"}");
        assertFalse(value.contains("fakeBearerCredential"));
        assertFalse(value.contains("ZmFrZTpzZWNyZXQ="));
        assertFalse(value.contains("fakeJsonBearer"));
    }

    @Test public void escapedQuotesCannotExposeTheRestOfAJsonCredential() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "{\"password\":\"fakePrefix\\\"fakeEscapedPasswordTail\","
                + "\"authorization\":\"Bearer fakePrefix\\\"fakeEscapedHeaderTail\"}");
        assertFalse(value.contains("fakeEscapedPasswordTail"));
        assertFalse(value.contains("fakeEscapedHeaderTail"));
    }

    @Test public void incompleteQuotedCredentialsRemainRedacted() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "native failure: password=\"fakePrefix fakeIncompleteCredentialTail");
        assertFalse(value.contains("fakeIncompleteCredentialTail"));
        assertTrue(value.contains("native failure"));
    }

    @Test public void repeatedSanitizationKeepsRedactedDiagnosticsStable() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "key=fakeKey\nAuthorization: Bearer fakeHeader\n"
                + "{\"psk\":\"fakePsk\"}\n"
                + "gpgbridge:v1:AbCd012345_-\nhttps://login.tailscale.com/a/fakeLogin");
        assertEquals(value, RemoteAgentDiagnosticBuffer.sanitize(value));
    }

    @Test public void redactsTailscaleAndHeadscaleLoginPaths() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "Login https://login.tailscale.com/a/fakeTailscaleLogin\n"
                + "Register https://headscale.example/register/fakeHeadscaleLogin\n"
                + "Auth https://headscale.example/auth/fakeHeadscaleAuth");
        assertFalse(value.contains("fakeTailscaleLogin"));
        assertFalse(value.contains("fakeHeadscaleLogin"));
        assertFalse(value.contains("fakeHeadscaleAuth"));
        assertTrue(value.contains("headscale.example"));
    }

    @Test public void redactsUrlCredentialsWhilePreservingDestination() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "Get https://fakeUsername:fakeUrlPassword@control.example:443/api: connection refused");
        assertFalse(value.contains("fakeUsername"));
        assertFalse(value.contains("fakeUrlPassword"));
        assertTrue(value.contains("control.example:443"));
        assertTrue(value.contains("connection refused"));
    }

    @Test public void redactsPrivateKeyArmorIncludingUnterminatedBlocks() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nfakePrivateKeyBody\n"
                + "-----END PGP PRIVATE KEY BLOCK-----\nafter");
        assertFalse(value.contains("fakePrivateKeyBody"));
        assertTrue(value.contains("before"));
        assertTrue(value.contains("after"));
        String incomplete = RemoteAgentDiagnosticBuffer.sanitize(
                "-----BEGIN RSA PRIVATE KEY-----\nfakeUnterminatedPrivateBody");
        assertFalse(incomplete.contains("fakeUnterminatedPrivateBody"));
    }

    @Test public void preservesUsefulNetworkFailureDetails() {
        String message = "ProxyError: dial tcp 100.101.102.103:17389: connect: no route to host\n"
                + "DNS lookup controlplane.tailscale.com failed; HTTP 403 Forbidden; "
                + "tls: failed to verify certificate";
        String value = RemoteAgentDiagnosticBuffer.sanitize(message);
        assertTrue(value.contains("ProxyError"));
        assertTrue(value.contains("100.101.102.103:17389"));
        assertTrue(value.contains("no route to host"));
        assertTrue(value.contains("controlplane.tailscale.com"));
        assertTrue(value.contains("403 Forbidden"));
        assertTrue(value.contains("failed to verify certificate"));
    }

    @Test public void nestedFailureRetainsRootCauseAndStackLocation() {
        IOException cause = new IOException("DNS lookup failed; password=fakeNestedPassword");
        cause.setStackTrace(new StackTraceElement[] {
                new StackTraceElement("diagnostics.NativeBridge", "start", "NativeBridge.java", 91)
        });
        RuntimeException wrapped = new RuntimeException("Proxy bridge failed", cause);
        String summary = RemoteAgentDiagnosticBuffer.failure(wrapped);
        assertTrue(summary.contains("IOException"));
        assertTrue(summary.contains("DNS lookup failed"));
        assertFalse(summary.contains("fakeNestedPassword"));
        String details = RemoteAgentDiagnosticBuffer.details("Tailscale startup", wrapped);
        assertTrue(details.contains("Tailscale startup"));
        assertTrue(details.contains("NativeBridge.java:91"));
        assertFalse(details.contains("fakeNestedPassword"));
        assertTrue(details.length() <= RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS);
    }

    @Test(timeout = 2000) public void cyclicFailureChainsCannotHangDiagnostics() {
        Exception first = new Exception("first cause");
        Exception second = new Exception("second cause", first);
        first.initCause(second);
        String value = RemoteAgentDiagnosticBuffer.failure(first);
        assertTrue(value.contains("first cause"));
        assertTrue(value.length() <= RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS);
    }

    @Test public void redactsBeforeEntryTruncation() {
        String value = RemoteAgentDiagnosticBuffer.sanitize(
                repeat("x", RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS - 12)
                + " password=fakeCredentialAtBoundary trailing detail");
        assertFalse(value.contains("fakeCredential"));
        assertTrue(value.length() <= RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS);
    }

    @Test public void boundsEntriesAndTotalCharactersAndKeepsSnapshotIndependent() {
        RemoteAgentDiagnosticBuffer buffer = new RemoteAgentDiagnosticBuffer();
        for (int index = 0; index < RemoteAgentDiagnosticBuffer.MAX_ENTRIES * 2; index++) {
            buffer.add(RemoteAgentDiagnosticBuffer.Level.INFO,
                    "entry " + index + " " + repeat("x", RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS * 2));
        }
        List<RemoteAgentDiagnosticBuffer.Entry> snapshot = buffer.snapshot();
        assertFalse(snapshot.isEmpty());
        assertTrue(snapshot.size() <= RemoteAgentDiagnosticBuffer.MAX_ENTRIES);
        int total = 0;
        for (RemoteAgentDiagnosticBuffer.Entry entry : snapshot) {
            assertTrue(entry.text.length() <= RemoteAgentDiagnosticBuffer.MAX_ENTRY_CHARS);
            total += entry.text.length();
        }
        assertTrue(total <= RemoteAgentDiagnosticBuffer.MAX_TOTAL_CHARS);
        assertTrue(snapshot.get(snapshot.size() - 1).text.startsWith(
                "entry " + (RemoteAgentDiagnosticBuffer.MAX_ENTRIES * 2 - 1) + " "));
        int before = snapshot.size();
        String first = snapshot.get(0).text;
        buffer.clear();
        assertTrue(buffer.snapshot().isEmpty());
        buffer.add(RemoteAgentDiagnosticBuffer.Level.ERROR, "new event");
        assertEquals(before, snapshot.size());
        assertEquals(first, snapshot.get(0).text);
    }

    @Test(timeout = 5000) public void concurrentWritersKeepTheBufferBounded() throws Exception {
        RemoteAgentDiagnosticBuffer buffer = new RemoteAgentDiagnosticBuffer();
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread[] writers = new Thread[4];
        for (int index = 0; index < writers.length; index++) {
            final int writer = index;
            writers[index] = new Thread(() -> {
                try {
                    start.await();
                    for (int entry = 0; entry < 300; entry++) {
                        buffer.add(RemoteAgentDiagnosticBuffer.Level.WARN,
                                "writer " + writer + " event " + entry);
                        buffer.snapshot();
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            });
            writers[index].start();
        }
        start.countDown();
        for (Thread writer : writers) writer.join();
        if (failure.get() != null) throw new AssertionError(failure.get());
        assertEquals(RemoteAgentDiagnosticBuffer.MAX_ENTRIES, buffer.snapshot().size());
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) result.append(value);
        return result.toString();
    }
}
