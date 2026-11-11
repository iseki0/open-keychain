package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

import android.app.Application;
import android.content.Intent;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Field;
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
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.ui.LogDisplayActivity;

/** Regressions for the status refresh that previously laid out full Tailscale JSON on every tick. */
@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 28)
@LooperMode(LooperMode.Mode.PAUSED)
public class RemoteAgentActivityTest {
    private ActivityController<RemoteAgentActivity> controller;

    @Before public void resetStatus() throws Exception {
        publish(RemoteAgentStatus.initial());
        RemoteAgentDiagnostics.clear();
    }

    @After public void closeActivity() throws Exception {
        if (controller != null) controller.pause().stop().destroy();
        publish(RemoteAgentStatus.initial());
        RemoteAgentDiagnostics.clear();
    }

    @Test public void showsCompactSummaryAndKeepsLoginActionWorking() throws Exception {
        String url = "https://login.tailscale.com/a/private-login-token";
        publish(RemoteAgentStatus.parse("{\"BackendState\":\"NeedsLogin\","
                + "\"TailscaleIPs\":[\"100.64.0.1\"],\"Health\":[\"DNS unavailable\"],"
                + "\"AuthURL\":\"" + url + "\",\"Peer\":{\"hidden\":\"peer details\"}}"));
        RemoteAgentActivity activity = open();
        TextView status = field(activity, "status", TextView.class);
        String text = status.getText().toString();
        assertTrue(text.contains("NeedsLogin"));
        assertTrue(text.contains("100.64.0.1"));
        assertTrue(text.contains("DNS unavailable"));
        assertFalse(text.contains("AuthURL"));
        assertFalse(text.contains("private-login-token"));
        assertFalse(text.contains("peer details"));
        assertTrue(text.length() <= 1536);
        assertEquals(12, status.getMaxLines());
        Button login = field(activity, "login", Button.class);
        assertTrue(login.isEnabled());
        login.performClick();
        Intent launch = shadowOf(activity).getNextStartedActivity();
        assertEquals(Intent.ACTION_VIEW, launch.getAction());
        assertEquals(url, launch.getDataString());
    }

    @Test public void unchangedPollingDoesNotResetTextAndPauseStopsRefresh() throws Exception {
        publish(RemoteAgentStatus.message("Connecting"));
        RemoteAgentActivity activity = open();
        TextView status = field(activity, "status", TextView.class);
        int[] textChanges = {0};
        status.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                textChanges[0]++;
            }
            @Override public void afterTextChanged(Editable editable) {}
        });
        shadowOf(Looper.getMainLooper()).idleFor(6, TimeUnit.SECONDS);
        assertEquals(0, textChanges[0]);
        // Even a fresh equivalent worker snapshot must not trigger TextView layout work.
        publish(RemoteAgentStatus.message("Connecting"));
        shadowOf(Looper.getMainLooper()).idleFor(2, TimeUnit.SECONDS);
        assertEquals(0, textChanges[0]);
        controller.pause();
        publish(RemoteAgentStatus.message("Disconnected"));
        shadowOf(Looper.getMainLooper()).idleFor(6, TimeUnit.SECONDS);
        assertEquals("Connecting", status.getText().toString());
        assertEquals(0, textChanges[0]);
        controller.resume();
        shadowOf(Looper.getMainLooper()).idle();
        assertEquals("Disconnected", status.getText().toString());
        assertEquals(1, textChanges[0]);
    }

    @Test public void diagnosticsRemainBeforeConfigurationAndOpenWithBoundedStatus() throws Exception {
        publish(RemoteAgentStatus.failure(repeat("connection failure ", 10000)));
        RemoteAgentActivity activity = open();
        ScrollView scroll = (ScrollView) ((android.view.ViewGroup) activity
                .findViewById(android.R.id.content)).getChildAt(0);
        LinearLayout content = (LinearLayout) scroll.getChildAt(0);
        int firstConfig = -1;
        int logButton = -1;
        Button log = null;
        for (int index = 0; index < content.getChildCount(); index++) {
            View child = content.getChildAt(index);
            if (firstConfig < 0 && child instanceof EditText) firstConfig = index;
            if (child instanceof Button && ((Button) child).getText().toString()
                    .equals(activity.getString(R.string.remote_agent_view_log))) {
                logButton = index;
                log = (Button) child;
            }
        }
        assertTrue(logButton >= 0 && logButton < firstConfig);
        assertTrue(field(activity, "status", TextView.class).getText().length() <= 1536);
        assertNotNull(log);
        assertTrue(log.performClick());
        Intent launch = shadowOf(activity).getNextStartedActivity();
        assertEquals(LogDisplayActivity.class.getName(), launch.getComponent().getClassName());
    }

    private RemoteAgentActivity open() {
        controller = Robolectric.buildActivity(RemoteAgentActivity.class).setup();
        shadowOf(Looper.getMainLooper()).idle();
        return controller.get();
    }

    private static void publish(RemoteAgentStatus status) throws Exception {
        Field value = RemoteAgentService.class.getDeclaredField("currentStatus");
        value.setAccessible(true);
        value.set(null, status);
    }

    private static <T> T field(Object object, String name, Class<T> type) throws Exception {
        Field value = object.getClass().getDeclaredField(name);
        value.setAccessible(true);
        return type.cast(value.get(object));
    }

    private static String repeat(String value, int count) {
        StringBuilder text = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) text.append(value);
        return text.toString();
    }
}
