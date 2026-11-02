package org.sufficientlysecure.keychain.remoteagent;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.app.NotificationManagerCompat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.json.JSONObject;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningRepository;

public final class RemoteAgentActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private EditText hostname, control, peers;
    private TextView status;
    private Button login;
    private String loginURL;
    private final Runnable refresh = new Runnable() {
        @Override public void run() { refreshStatus(); handler.postDelayed(this, 2000); }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle(R.string.remote_agent_title);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
        TextView explanation = new TextView(this);
        explanation.setText(R.string.remote_agent_explanation);
        content.addView(explanation);
        SharedPreferences settings = RemoteAgentConfig.preferences(this);
        hostname = field(content, R.string.remote_agent_hostname, settings.getString("hostname", "openkeychain"));
        control = field(content, R.string.remote_agent_control, settings.getString("control", ""));
        peers = field(content, R.string.remote_agent_peers, settings.getString("peers", ""));
        button(content, R.string.remote_agent_choose_keys, this::chooseKeys);
        button(content, R.string.remote_agent_connect, this::connect);
        button(content, R.string.remote_agent_disconnect,
                () -> stopService(new Intent(this, RemoteAgentService.class)));
        login = button(content, R.string.remote_agent_login, () -> {
            if (loginURL != null) startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(loginURL)));
        });
        login.setEnabled(false);
        status = new TextView(this);
        status.setTextIsSelectable(true);
        content.addView(status);
    }

    private EditText field(LinearLayout parent, int hint, String value) {
        TextView label = new TextView(this);
        label.setText(hint);
        parent.addView(label);
        EditText result = new EditText(this);
        result.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        result.setSingleLine(true);
        result.setText(value);
        parent.addView(result);
        return result;
    }

    private Button button(LinearLayout parent, int text, Runnable action) {
        Button button = new Button(this);
        button.setText(text);
        button.setOnClickListener(view -> action.run());
        parent.addView(button);
        return button;
    }

    private void chooseKeys() {
        new Thread(() -> {
            try {
                List<RemoteSigningKey> keys = new RemoteSigningRepository(this).listAvailableKeys();
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    if (keys.isEmpty()) { message(R.string.remote_agent_no_keys); return; }
                    Set<String> selected = new HashSet<>(RemoteAgentConfig.fingerprints(this));
                    CharSequence[] labels = new CharSequence[keys.size()];
                    boolean[] checked = new boolean[keys.size()];
                    for (int i = 0; i < keys.size(); i++) {
                        RemoteSigningKey key = keys.get(i);
                        labels[i] = key.userId + "\n" + key.fingerprint;
                        checked[i] = selected.contains(key.fingerprint);
                    }
                    new AlertDialog.Builder(this).setTitle(R.string.remote_agent_choose_keys)
                            .setMultiChoiceItems(labels, checked, (dialog, position, enabled) -> {
                                String fingerprint = keys.get(position).fingerprint;
                                if (enabled) selected.add(fingerprint); else selected.remove(fingerprint);
                            }).setPositiveButton(android.R.string.ok, (dialog, which) -> {
                                RemoteAgentConfig.preferences(this).edit().putStringSet("fingerprints", selected).apply();
                                // Reconnect explicitly so revoked selections take effect immediately.
                                stopService(new Intent(this, RemoteAgentService.class));
                                message(R.string.remote_agent_reconnect);
                            }).setNegativeButton(android.R.string.cancel, null).show();
                });
            } catch (Exception e) { runOnUiThread(() -> message(R.string.remote_agent_no_keys)); }
        }, "signing-key-list").start();
    }

    private void connect() {
        if (RemoteAgentService.isRunning()) { message(R.string.remote_agent_reconnect); return; }
        String hostValue = hostname.getText().toString().trim();
        String controlValue = control.getText().toString().trim();
        String peersValue = peers.getText().toString().trim();
        if (!hostValue.matches("[a-zA-Z0-9][a-zA-Z0-9-]{0,62}")) {
            hostname.setError(getString(R.string.remote_agent_invalid_hostname)); return;
        }
        if (!controlValue.isEmpty()) {
            Uri uri = Uri.parse(controlValue);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null) {
                control.setError(getString(R.string.remote_agent_invalid_control)); return;
            }
        }
        if (!peersValue.isEmpty() && !peersValue.matches("[A-Za-z0-9_-]+(\\s*,\\s*[A-Za-z0-9_-]+)*")) {
            peers.setError(getString(R.string.remote_agent_invalid_peers)); return;
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 17373);
            return;
        }
        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            message(R.string.remote_agent_notifications_required); return;
        }
        RemoteAgentConfig.preferences(this).edit().putString("hostname", hostValue)
                .putString("control", controlValue).putString("peers", peersValue.replaceAll("\\s", "")).apply();
        Intent service = new Intent(this, RemoteAgentService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
    }

    private void refreshStatus() {
        String value = RemoteAgentService.status();
        status.setText(value);
        loginURL = null;
        try {
            String auth = new JSONObject(value).optString("AuthURL");
            Uri uri = Uri.parse(auth);
            if ("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null)
                loginURL = auth;
        } catch (Exception ignored) {}
        login.setEnabled(loginURL != null);
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (requestCode == 17373) {
            if (grants.length > 0 && grants[0] == PackageManager.PERMISSION_GRANTED) connect();
            else message(R.string.remote_agent_notifications_required);
        }
    }

    private void message(int resource) { Toast.makeText(this, resource, Toast.LENGTH_LONG).show(); }
    @Override protected void onResume() { super.onResume(); handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh); super.onPause(); }
}
