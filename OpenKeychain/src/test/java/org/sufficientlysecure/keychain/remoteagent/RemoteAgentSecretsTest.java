package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 28)
public class RemoteAgentSecretsTest {
    private static final String KEY = "1111111111111111111111111111111111111111";
    private static final String OTHER_KEY = "2222222222222222222222222222222222222222";
    private Context context;
    private SecretKey wrappingKey = new SecretKeySpec(new byte[32], "AES");

    @Before public void useSoftwareKey() {
        context = RuntimeEnvironment.getApplication();
        RemoteAgentSecrets.setKeySourceForTesting(() -> wrappingKey);
    }

    @After public void restoreKeySource() {
        RemoteAgentSecrets.clearPassphrases(context);
        RemoteAgentSecrets.clearBridgeState(context);
        RemoteAgentSecrets.setKeySourceForTesting(null);
        RemoteAgentDiagnostics.clear();
    }

    @Test public void passphrasesRoundTripEncryptedAndInputIsWiped() throws Exception {
        char[] input = "  密钥 passphrase 🔑 ".toCharArray();
        RemoteAgentSecrets.savePassphrase(context, KEY, input);
        assertArrayEquals(new char[input.length], input);
        assertTrue(RemoteAgentSecrets.hasPassphrase(context, KEY));
        assertFalse(RemoteAgentSecrets.hasPassphrase(context, OTHER_KEY));
        assertArrayEquals("  密钥 passphrase 🔑 ".toCharArray(), RemoteAgentSecrets.passphrase(context, KEY));
        assertNull(RemoteAgentSecrets.passphrase(context, OTHER_KEY));
        String stored = raw().getString("passphrase:" + KEY, null);
        assertNotNull(stored);
        assertFalse(new String(android.util.Base64.decode(stored, 0), StandardCharsets.ISO_8859_1).contains("passphrase"));
    }

    @Test public void emptyValueRemovesAndClearRemovesOnlyPassphrases() throws Exception {
        RemoteAgentSecrets.savePassphrase(context, KEY, "one".toCharArray());
        RemoteAgentSecrets.savePassphrase(context, OTHER_KEY, "two".toCharArray());
        RemoteAgentSecrets.saveBridgeState(context, "{\"version\":1}");
        RemoteAgentSecrets.savePassphrase(context, KEY, new char[0]);
        assertFalse(RemoteAgentSecrets.hasPassphrase(context, KEY));
        assertArrayEquals("two".toCharArray(), RemoteAgentSecrets.passphrase(context, OTHER_KEY));
        RemoteAgentSecrets.clearPassphrases(context);
        assertFalse(RemoteAgentSecrets.hasPassphrase(context, OTHER_KEY));
        assertEquals("{\"version\":1}", RemoteAgentSecrets.bridgeState(context));
    }

    @Test public void ciphertextsAreBoundToTheirEntry() throws Exception {
        RemoteAgentSecrets.savePassphrase(context, KEY, "secret".toCharArray());
        String sealed = raw().getString("passphrase:" + KEY, null);
        raw().edit().putString("passphrase:" + OTHER_KEY, sealed).commit();
        assertNull(RemoteAgentSecrets.passphrase(context, OTHER_KEY));
        assertFalse("an undecryptable entry is removed", RemoteAgentSecrets.hasPassphrase(context, OTHER_KEY));
        assertArrayEquals("secret".toCharArray(), RemoteAgentSecrets.passphrase(context, KEY));
    }

    @Test public void aDifferentDeviceKeyCannotReadAndEntriesAreDropped() throws Exception {
        RemoteAgentSecrets.savePassphrase(context, KEY, "secret".toCharArray());
        RemoteAgentSecrets.saveBridgeState(context, "{\"state\":true}");
        byte[] other = new byte[32];
        other[0] = 1;
        wrappingKey = new SecretKeySpec(other, "AES");
        assertNull(RemoteAgentSecrets.passphrase(context, KEY));
        assertFalse(RemoteAgentSecrets.hasPassphrase(context, KEY));
        assertNull(RemoteAgentSecrets.bridgeState(context));
        assertFalse(RemoteAgentSecrets.hasBridgeState(context));
    }

    @Test public void tamperedEntriesAreRejected() throws Exception {
        RemoteAgentSecrets.saveBridgeState(context, "{\"state\":true}");
        byte[] sealed = android.util.Base64.decode(raw().getString("bridge-state", null), 0);
        sealed[sealed.length - 1] ^= 1;
        raw().edit().putString("bridge-state", android.util.Base64.encodeToString(sealed, 2)).commit();
        assertNull(RemoteAgentSecrets.bridgeState(context));
        raw().edit().putString("bridge-state", "not base64 !!!").commit();
        assertNull(RemoteAgentSecrets.bridgeState(context));
    }

    @Test public void bridgeStateRoundTripsAndClears() throws Exception {
        assertFalse(RemoteAgentSecrets.hasBridgeState(context));
        RemoteAgentSecrets.saveBridgeState(context, "{\"private\":\"abc\"}");
        assertTrue(RemoteAgentSecrets.hasBridgeState(context));
        assertEquals("{\"private\":\"abc\"}", RemoteAgentSecrets.bridgeState(context));
        RemoteAgentSecrets.clearBridgeState(context);
        assertNull(RemoteAgentSecrets.bridgeState(context));
    }

    @Test public void approvalPassphrasePrefersTheConnectionPrefillThenTheSavedValue() throws Exception {
        assertNull(RemoteAgentService.approvalPassphrase(context, KEY));
        RemoteAgentSecrets.savePassphrase(context, KEY, "saved".toCharArray());
        assertArrayEquals("saved".toCharArray(), RemoteAgentService.approvalPassphrase(context, KEY));
    }

    @Test public void gitSubjectShowsOnlyTheEscapedFirstMessageLine() {
        String commit = "tree " + repeat('a', 40) + "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\n"
                + "Fix‮evil 󠁁tag\tline\nsecond line\n";
        assertEquals("Fix\\u{202E}evil \\u{E0041}tag\\u{9}line",
                RemoteAgentService.gitSubject(commit.getBytes(StandardCharsets.UTF_8)));
        String longCommit = "tree x\n\n" + repeat('b', 200);
        String subject = RemoteAgentService.gitSubject(longCommit.getBytes(StandardCharsets.UTF_8));
        assertEquals(121, subject.length());
        assertTrue(subject.endsWith("…"));
        assertEquals("", RemoteAgentService.gitSubject("no body".getBytes(StandardCharsets.UTF_8)));
    }

    private SharedPreferences raw() {
        return context.getSharedPreferences("remote-signing-secrets", Context.MODE_PRIVATE);
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }
}
