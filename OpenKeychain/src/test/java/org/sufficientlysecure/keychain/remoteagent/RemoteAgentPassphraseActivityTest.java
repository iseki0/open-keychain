package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

import android.app.AlertDialog;
import android.app.Application;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.EditText;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.LooperMode;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 28)
@LooperMode(LooperMode.Mode.PAUSED)
public class RemoteAgentPassphraseActivityTest {
    private static final String KEY = "1111111111111111111111111111111111111111";
    private static final String OTHER_KEY = "2222222222222222222222222222222222222222";
    private final List<RemoteAgentService> services = new ArrayList<>();
    private ActivityController<RemoteAgentActivity> controller;
    private RemoteAgentActivity activity;
    private boolean paused;

    @Before public void openSettings() throws Exception {
        activateNewSession();
        controller = Robolectric.buildActivity(RemoteAgentActivity.class).setup();
        activity = controller.get();
        shadowOf(Looper.getMainLooper()).idle();
    }

    @After public void closeSettings() throws Exception {
        if (!paused) controller.pause();
        controller.stop().destroy();
        RemoteAgentService.clearPrefilledPassphrases();
        setActive(null);
        for (RemoteAgentService service : services) {
            Field cache = RemoteAgentService.class.getDeclaredField("passphrases");
            cache.setAccessible(true);
            ((SigningPassphraseCache) cache.get(service)).clear();
            for (String name : new String[] {"workers", "statusPoller", "bridgeControl"}) {
                Field field = RemoteAgentService.class.getDeclaredField(name);
                field.setAccessible(true);
                ((ExecutorService) field.get(service)).shutdownNow();
            }
        }
    }

    @Test public void editorSavesTheExactPassphraseForTheChosenKeyAndClearsItsField() throws Exception {
        AlertDialog dialog = edit(KEY);
        EditText password = input(dialog);
        assertFalse(password.isSaveEnabled());
        assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, password.getImportantForAutofill());
        assertTrue((dialog.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0);
        password.setText("  密钥 passphrase  ");
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
        shadowOf(Looper.getMainLooper()).idle();
        assertArrayEquals("  密钥 passphrase  ".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
        assertNull(RemoteAgentService.prefilledPassphrase(OTHER_KEY));
        assertFalse(dialog.isShowing());
        assertEquals(0, password.length());
    }

    @Test public void cancelPreservesTheSavedValueAndClearRemovesOnlyTheChosenKey() throws Exception {
        RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "saved".toCharArray());
        RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), OTHER_KEY, "other".toCharArray());
        AlertDialog dialog = edit(KEY);
        EditText password = input(dialog);
        assertEquals("saved", password.getText().toString());
        password.setText("unsaved edit");
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
        shadowOf(Looper.getMainLooper()).idle();
        assertEquals(0, password.length());
        assertArrayEquals("saved".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
        AlertDialog clear = edit(KEY);
        EditText cleared = input(clear);
        clear.getButton(AlertDialog.BUTTON_NEUTRAL).performClick();
        shadowOf(Looper.getMainLooper()).idle();
        assertEquals(0, cleared.length());
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
        assertArrayEquals("other".toCharArray(), RemoteAgentService.prefilledPassphrase(OTHER_KEY));
    }

    @Test public void leavingSettingsDismissesAndWipesAnUnsavedEditor() throws Exception {
        AlertDialog dialog = edit(KEY);
        EditText password = input(dialog);
        password.setText("unsaved secret");
        controller.pause();
        paused = true;
        shadowOf(Looper.getMainLooper()).idle();
        assertFalse(dialog.isShowing());
        assertEquals(0, password.length());
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
    }

    @Test public void reconnectDismissesThePreviousSessionsEditorWithoutSavingIt() throws Exception {
        AlertDialog dialog = edit(KEY);
        EditText password = input(dialog);
        password.setText("old session secret");
        activateNewSession();
        shadowOf(Looper.getMainLooper()).idleFor(2, TimeUnit.SECONDS);
        assertFalse(dialog.isShowing());
        assertEquals(0, password.length());
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
    }

    private AlertDialog edit(String fingerprint) throws Exception {
        Constructor<RemoteSigningKey> constructor = RemoteSigningKey.class.getDeclaredConstructor(
                long.class, long.class, String.class, String.class, byte[].class, String.class,
                String.class, long.class, String.class);
        constructor.setAccessible(true);
        RemoteSigningKey key = constructor.newInstance(11L, 12L, fingerprint, null, null,
                "Test signer", "3333333333333333333333333333333333333333", 0L, "RSA");
        Method edit = RemoteAgentActivity.class.getDeclaredMethod("editPassphrase", RemoteSigningKey.class);
        edit.setAccessible(true);
        edit.invoke(activity, key);
        Field field = RemoteAgentActivity.class.getDeclaredField("passphraseDialog");
        field.setAccessible(true);
        return (AlertDialog) field.get(activity);
    }

    private void activateNewSession() throws Exception {
        RemoteAgentService service = new RemoteAgentService();
        services.add(service);
        setActive(service);
    }

    private static void setActive(RemoteAgentService service) throws Exception {
        Field field = RemoteAgentService.class.getDeclaredField("active");
        field.setAccessible(true);
        field.set(null, service);
    }

    private static EditText input(AlertDialog dialog) {
        EditText result = findInput((ViewGroup) dialog.getWindow().getDecorView());
        assertNotNull(result);
        return result;
    }

    private static EditText findInput(ViewGroup parent) {
        for (int index = 0; index < parent.getChildCount(); index++) {
            View child = parent.getChildAt(index);
            if (child instanceof EditText) return (EditText) child;
            if (child instanceof ViewGroup) {
                EditText result = findInput((ViewGroup) child);
                if (result != null) return result;
            }
        }
        return null;
    }
}
