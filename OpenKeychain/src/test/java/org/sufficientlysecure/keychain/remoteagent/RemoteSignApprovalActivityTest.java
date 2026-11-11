package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

import android.app.Application;
import android.content.Intent;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 28)
public class RemoteSignApprovalActivityTest {
    private static final String KEY = "1111111111111111111111111111111111111111";
    private static final String OTHER_KEY = "2222222222222222222222222222222222222222";
    private RemoteAgentService service;
    private ActivityController<RemoteSignApprovalActivity> controller;

    @Before public void startLocalSession() throws Exception {
        service = new RemoteAgentService();
        Field active = RemoteAgentService.class.getDeclaredField("active");
        active.setAccessible(true);
        active.set(null, service);
        approvals().clear();
    }

    @After public void closeLocalSession() throws Exception {
        if (controller != null) controller.pause().stop().destroy();
        for (SigningApproval request : approvals().values()) request.deny();
        approvals().clear();
        RemoteAgentService.clearPrefilledPassphrases();
        Field active = RemoteAgentService.class.getDeclaredField("active");
        active.setAccessible(true);
        active.set(null, null);
        for (String name : new String[] {"workers", "statusPoller", "bridgeControl"}) {
            Field field = RemoteAgentService.class.getDeclaredField(name);
            field.setAccessible(true);
            ((ExecutorService) field.get(service)).shutdownNow();
        }
    }

    @Test public void assuanPrefillStillRequiresExplicitApprovalAndPreservesCachedSecret() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "saved secret".toCharArray()));
        SigningApproval request = request(KEY, null);
        RemoteSignApprovalActivity activity = open(request.id);
        EditText password = password(activity);
        assertEquals("saved secret", password.getText().toString());
        assertFalse(request.answer.isDone());
        assertFalse(password.isSaveEnabled());
        assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, password.getImportantForAutofill());
        assertEquals(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD, password.getInputType());
        assertTrue((activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0);
        button(activity, R.string.remote_agent_approve).performClick();
        assertArrayEquals("saved secret".toCharArray(), request.answer.getNow(null));
        assertEquals(0, password.length());
        assertArrayEquals("saved secret".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
    }

    @Test public void bridgePrefillCanBeEditedBeforeApproving() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "old secret".toCharArray()));
        SigningApproval request = request(KEY, "tree abc\n\nA commit preview");
        RemoteSignApprovalActivity activity = open(request.id);
        EditText password = password(activity);
        assertEquals("old secret", password.getText().toString());
        assertFalse(request.answer.isDone());
        password.setText("replacement secret");
        button(activity, R.string.remote_agent_approve).performClick();
        assertArrayEquals("replacement secret".toCharArray(), request.answer.getNow(null));
        assertArrayEquals("old secret".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
    }

    @Test public void anotherKeysPrefillDoesNotAppearAndAnUnprotectedKeyCanBeApproved() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), OTHER_KEY, "different key".toCharArray()));
        SigningApproval request = request(KEY, null);
        RemoteSignApprovalActivity activity = open(request.id);
        assertEquals(0, password(activity).length());
        assertFalse(request.answer.isDone());
        button(activity, R.string.remote_agent_approve).performClick();
        assertNotNull(request.answer.getNow(null));
        assertArrayEquals(new char[0], request.answer.getNow(null));
    }

    @Test public void denyingAPrefilledRequestClearsTheFieldWithoutApproving() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "saved secret".toCharArray()));
        SigningApproval request = request(KEY, null);
        RemoteSignApprovalActivity activity = open(request.id);
        EditText password = password(activity);
        button(activity, R.string.remote_agent_deny).performClick();
        controller.pause().stop().destroy();
        controller = null;
        assertTrue(request.answer.isDone());
        assertNull(request.answer.getNow(null));
        assertEquals(0, password.length());
        assertArrayEquals("saved secret".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
    }

    @Test public void invalidAndExpiredRequestsCannotObtainAPrefill() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "saved secret".toCharArray()));
        RemoteSignApprovalActivity invalid = open("missing-request");
        assertTrue(invalid.isFinishing());
        assertNull(password(invalid));
        controller.pause().stop().destroy();
        controller = null;
        SigningApproval expired = request(KEY, null);
        expired.deny();
        RemoteSignApprovalActivity closed = open(expired.id);
        assertTrue(closed.isFinishing());
        assertNull(password(closed));
        assertNull(expired.answer.getNow(null));
    }

    @Test public void revokingAnOpenRequestImmediatelyClearsItsVisiblePassphrase() throws Exception {
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY,
                "saved secret".toCharArray()));
        SigningApproval request = request(KEY, "commit preview");
        RemoteSignApprovalActivity activity = open(request.id);
        EditText password = password(activity);
        assertEquals("saved secret", password.getText().toString());
        // Timeout, service shutdown and bridge revocation all complete this same capability.
        request.deny();
        shadowOf(Looper.getMainLooper()).idle();
        assertTrue(activity.isFinishing());
        assertEquals(0, password.length());
        assertTrue(request.answer.isDone());
        assertNull(request.answer.getNow(null));
    }

    private RemoteSignApprovalActivity open(String id) {
        Intent intent = new Intent().putExtra("request", id);
        controller = Robolectric.buildActivity(RemoteSignApprovalActivity.class, intent).setup();
        return controller.get();
    }

    private static SigningApproval request(String fingerprint, String preview) throws Exception {
        Constructor<RemoteSigningKey> constructor = RemoteSigningKey.class.getDeclaredConstructor(
                long.class, long.class, String.class, String.class, byte[].class, String.class,
                String.class, long.class, String.class);
        constructor.setAccessible(true);
        RemoteSigningKey key = constructor.newInstance(11L, 12L, fingerprint, null, null,
                "Test signer", "3333333333333333333333333333333333333333", 0L, "RSA");
        SigningApproval request = new SigningApproval("test peer", key, 8, new byte[32], preview);
        approvals().put(request.id, request);
        return request;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, SigningApproval> approvals() throws Exception {
        Field field = RemoteAgentService.class.getDeclaredField("approvals");
        field.setAccessible(true);
        return (Map<String, SigningApproval>) field.get(null);
    }

    private static EditText password(RemoteSignApprovalActivity activity) throws Exception {
        Field field = RemoteSignApprovalActivity.class.getDeclaredField("password");
        field.setAccessible(true);
        return (EditText) field.get(activity);
    }

    private static Button button(RemoteSignApprovalActivity activity, int label) {
        return findButton((ViewGroup) activity.findViewById(android.R.id.content), activity.getString(label));
    }

    private static Button findButton(ViewGroup parent, String label) {
        for (int index = 0; index < parent.getChildCount(); index++) {
            View child = parent.getChildAt(index);
            if (child instanceof Button && ((Button) child).getText().toString().equals(label)) return (Button) child;
            if (child instanceof ViewGroup) {
                Button result = findButton((ViewGroup) child, label);
                if (result != null) return result;
            }
        }
        return null;
    }
}
