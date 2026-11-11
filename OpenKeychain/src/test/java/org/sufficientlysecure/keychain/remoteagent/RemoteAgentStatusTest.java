package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application = android.app.Application.class, manifest = Config.NONE, sdk = 28)
public class RemoteAgentStatusTest {
    @Test public void extractsOnlySummaryFieldsAndPreservesLoginUrl() {
        RemoteAgentStatus status = RemoteAgentStatus.parse("{\"BackendState\":\"Running\","
                + "\"AuthURL\":\"https://login.tailscale.com/a/example\","
                + "\"TailscaleIPs\":[\"100.64.0.1\",\"fd7a:115c:a1e0::1\"],"
                + "\"Health\":[\"DNS unavailable\"],\"Peer\":{\"peer\":{\"large\":\"ignored\"}}}");
        assertEquals("Running", status.backendState);
        assertEquals("100.64.0.1, fd7a:115c:a1e0::1", status.addresses);
        assertEquals("DNS unavailable", status.health);
        assertEquals("https://login.tailscale.com/a/example", status.loginUrl);
        assertNull(status.message);
        assertFalse(status.failed);
    }

    @Test public void rejectsHugeLegacyStatusBeforeParsingItsMalformedJson() {
        String oversized = "not even JSON" + repeat("x", RemoteAgentStatus.MAX_JSON_CHARS);
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> RemoteAgentStatus.parse(oversized));
        assertTrue(failure.getMessage().contains("size limit"));
        assertNull(failure.getCause());
    }

    @Test public void rejectsOversizedArraysAndDeeplyNestedGraphs() {
        assertThrows(IllegalArgumentException.class, () -> RemoteAgentStatus.parse(
                "{\"Peer\":[" + repeat("0,", 9000) + "0]}"));
        String nested = "{\"Peer\":" + repeat("[", 40) + "0" + repeat("]", 40) + "}";
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> RemoteAgentStatus.parse(nested));
        assertTrue(failure.getMessage().contains("nested too deeply"));
    }

    @Test public void rejectsMalformedJsonAndWrongFieldTypesWithoutStringifyingThem() {
        for (String json : new String[] {"{", "[]", "{}{}", "{\"BackendState\":{\"huge\":[]}}",
                "{\"AuthURL\":[\"https://example.org\"]}", "{\"Health\":\"wrong\"}",
                "{\"TailscaleIPs\":[{\"wrong\":\"shape\"}]}", "{\"BackendState\":true}"}) {
            assertThrows(json, IllegalArgumentException.class, () -> RemoteAgentStatus.parse(json));
        }
    }

    @Test public void nullAndMissingOptionalFieldsAreEmpty() {
        RemoteAgentStatus empty = RemoteAgentStatus.parse("{}");
        assertEquals(empty, RemoteAgentStatus.parse(
                "{\"BackendState\":null,\"TailscaleIPs\":null,\"Health\":null,\"AuthURL\":null}"));
        assertEquals("", empty.backendState);
        assertEquals("", empty.addresses);
        assertEquals("", empty.health);
        assertNull(empty.loginUrl);
    }

    @Test public void boundsEveryDisplayFieldAndMarksTruncation() throws Exception {
        JSONArray addresses = new JSONArray();
        JSONArray health = new JSONArray();
        for (int index = 0; index < 12; index++) addresses.put(index + repeat("a", 80));
        for (int index = 0; index < 8; index++) health.put(index + repeat("h", 300));
        JSONObject json = new JSONObject().put("BackendState", repeat("s", 300))
                .put("TailscaleIPs", addresses).put("Health", health);
        RemoteAgentStatus status = RemoteAgentStatus.parse(json.toString());
        assertTrue(status.backendState.length() <= 128);
        assertTrue(status.addresses.length() <= 512);
        assertTrue(status.health.length() <= 512);
        assertTrue(status.backendState.endsWith("\u2026"));
        assertTrue(status.addresses.endsWith("\u2026"));
        assertTrue(status.health.endsWith("\u2026"));
        assertFalse(status.addresses.contains("8aaa"));
        assertFalse(status.health.contains("4hhh"));
        assertTrue(status.backendState.length() + status.addresses.length() + status.health.length() < 2048);
    }

    @Test public void omitsUnsafeOrOversizedLoginUrlsRatherThanTruncatingCredentials() throws Exception {
        for (String url : new String[] {"http://login.example/a/secret", "javascript:alert(1)",
                "https:///missing-host", "https://user:password@login.example/a/secret",
                "https://login.example/a/secret\n", "https://login.example/\u202Ehidden",
                "https://login.example:99999/a/secret", "https://login.example/" + repeat("x", 4096)}) {
            assertNull(url, RemoteAgentStatus.parse(new JSONObject().put("AuthURL", url).toString()).loginUrl);
        }
        String boundary = "https://login.example/" + repeat("x", 4096 - "https://login.example/".length());
        assertEquals(boundary, RemoteAgentStatus.parse(new JSONObject().put("AuthURL", boundary).toString()).loginUrl);
    }

    @Test public void sanitizesControlCharactersAndKeepsJsonPunctuationInsideStrings() throws Exception {
        JSONObject json = new JSONObject().put("BackendState", "Run\u0000ning\u202Ehere")
                .put("Health", new JSONArray().put("first\nline").put("brackets [ { \\\" stay text"));
        RemoteAgentStatus status = RemoteAgentStatus.parse(json.toString());
        assertEquals("Run ning here", status.backendState);
        assertEquals("first line\nbrackets [ { \\\" stay text", status.health);
    }

    @Test public void lifecycleMessagesAreBoundedAndDoNotSplitSurrogatePairs() {
        String source = repeat("m", 1022) + "\uD83D\uDE00" + repeat("m", 10000);
        RemoteAgentStatus status = RemoteAgentStatus.failure(source);
        assertTrue(status.failed);
        assertTrue(status.message.length() <= 1024);
        assertEquals(repeat("m", 1022) + "\u2026", status.message);
        assertNull(status.loginUrl);
        assertEquals("Disconnected", RemoteAgentStatus.initial().message);
        assertEquals("", RemoteAgentStatus.message(null).message);
        assertFalse(RemoteAgentStatus.message("Connecting").failed);
    }

    @Test public void equalityIgnoresUnusedPeerFieldsAndDetectsVisibleChanges() {
        RemoteAgentStatus first = RemoteAgentStatus.parse("{\"BackendState\":\"Running\",\"Peer\":{\"one\":1}}");
        RemoteAgentStatus second = RemoteAgentStatus.parse("{\"BackendState\":\"Running\",\"Peer\":{\"two\":2}}");
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, RemoteAgentStatus.parse("{\"BackendState\":\"Stopped\"}"));
        assertNotEquals(RemoteAgentStatus.message("same"), RemoteAgentStatus.failure("same"));
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) result.append(value);
        return result.toString();
    }
}
