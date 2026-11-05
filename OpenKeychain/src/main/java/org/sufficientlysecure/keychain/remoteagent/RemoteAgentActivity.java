package org.sufficientlysecure.keychain.remoteagent;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.text.InputType;
import android.text.TextUtils;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.view.WindowManager;
import androidx.core.app.NotificationManagerCompat;
import java.util.HashSet;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningRepository;

public final class RemoteAgentActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private EditText hostname, control, peers;
    private CheckBox allNodes, allKeys;
    private TextView status;
    private Button login;
    private Button bridgePair;
    private TextView bridgeStatus;
    private AlertDialog passphraseDialog;
    private Object passphraseSession;
    private String loginURL;
    private RemoteAgentStatus shownStatus;
    private long shownBridgeExpiry = Long.MIN_VALUE;
    private final Runnable refresh = new Runnable() {
        @Override public void run() { refreshStatus(); handler.postDelayed(this, 2000); }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
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
        status = new TextView(this);
        status.setMaxLines(12);
        status.setEllipsize(TextUtils.TruncateAt.END);
        status.setTextIsSelectable(true);
        content.addView(status);
        button(content, R.string.remote_agent_view_log, this::openDiagnosticLog);
        button(content, R.string.remote_agent_clear_log, RemoteAgentDiagnostics::clear);
        SharedPreferences settings = RemoteAgentConfig.preferences(this);
        hostname = field(content, R.string.remote_agent_hostname, settings.getString("hostname", "openkeychain"));
        control = field(content, R.string.remote_agent_control, settings.getString("control", ""));
        peers = field(content, R.string.remote_agent_peers, settings.getString("peers", ""));
        allNodes = new CheckBox(this);
        allNodes.setText(R.string.remote_agent_all_nodes);
        allNodes.setChecked(peers.getText().toString().trim().isEmpty());
        peers.setEnabled(!allNodes.isChecked());
        allNodes.setOnCheckedChangeListener((button, checked) -> {
            peers.setEnabled(!checked);
            if (RemoteAgentService.isRunning()) {
                stopService(new Intent(this, RemoteAgentService.class));
                message(R.string.remote_agent_reconnect);
            }
        });
        content.addView(allNodes);
        allKeys = new CheckBox(this);
        allKeys.setText(R.string.remote_agent_all_keys);
        allKeys.setChecked(RemoteAgentConfig.allKeys(this));
        allKeys.setOnCheckedChangeListener((button, checked) -> {
            if (RemoteAgentConfig.allKeys(this) == checked) return;
            settings.edit().putBoolean("all_keys", checked).apply();
            if (RemoteAgentService.isRunning()) {
                stopService(new Intent(this, RemoteAgentService.class));
                message(R.string.remote_agent_reconnect);
            }
        });
        content.addView(allKeys);
        button(content, R.string.remote_agent_choose_keys, this::chooseKeys);
        button(content, R.string.remote_agent_prefill_password, this::choosePassphraseKey);
        button(content, R.string.remote_agent_clear_passwords, () -> {
            RemoteAgentService.clearPrefilledPassphrases();
            message(R.string.remote_agent_passwords_cleared);
        });
        button(content, R.string.remote_agent_connect, this::connect);
        button(content, R.string.remote_agent_disconnect,
                () -> stopService(new Intent(this, RemoteAgentService.class)));
        login = button(content, R.string.remote_agent_login, () -> {
            if (loginURL != null) startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(loginURL)));
        });
        login.setEnabled(false);
        bridgePair = button(content, R.string.remote_bridge_pair, this::pairBridge);
        button(content, R.string.remote_bridge_revoke, RemoteAgentService::revokeBridge);
        bridgeStatus = new TextView(this);
        content.addView(bridgeStatus);
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
                org.sufficientlysecure.keychain.daos.KeyRepository inventory =
                        org.sufficientlysecure.keychain.daos.KeyRepository.create(this);
                RemoteAgentDiagnostics.info("Local key inventory: package=" + getPackageName()
                        + ", public identities=" + inventory.getAllUnifiedKeyInfo().size()
                        + ", identities with secret material=" + inventory.getAllUnifiedKeyInfoWithSecret().size());
                RemoteSigningRepository repository = new RemoteSigningRepository(this);
                List<RemoteSigningKey> keys = repository.listAvailableKeys();
                int lines = 0;
                for (String line : repository.diagnosticInventory()) {
                    if (lines++ >= 48) { RemoteAgentDiagnostics.info("Additional key inventory rows omitted"); break; }
                    RemoteAgentDiagnostics.info(line);
                }
                RemoteAgentDiagnostics.info("Key selection: package=" + getPackageName()
                        + ", available signing keys=" + keys.size());
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    if (keys.isEmpty()) { message(R.string.remote_agent_no_keys); return; }
                    Set<String> selected = new HashSet<>(RemoteAgentConfig.fingerprints(this));
                    if (RemoteAgentConfig.allKeys(this)) {
                        for (RemoteSigningKey key : keys) selected.add(key.fingerprint);
                    }
                    CharSequence[] labels = new CharSequence[keys.size()];
                    boolean[] checked = new boolean[keys.size()];
                    for (int i = 0; i < keys.size(); i++) {
                        RemoteSigningKey key = keys.get(i);
                        labels[i] = key.userId + "\n" + key.algorithmName
                                + (key.keygrip == null ? " · " + getString(R.string.remote_agent_bridge_only) : "")
                                + "\n" + key.fingerprint;
                        checked[i] = selected.contains(key.fingerprint);
                    }
                    new AlertDialog.Builder(this).setTitle(R.string.remote_agent_choose_keys)
                            .setMultiChoiceItems(labels, checked, (dialog, position, enabled) -> {
                                String fingerprint = keys.get(position).fingerprint;
                                if (enabled) selected.add(fingerprint); else selected.remove(fingerprint);
                            }).setPositiveButton(android.R.string.ok, (dialog, which) -> {
                                RemoteAgentConfig.preferences(this).edit().putStringSet("fingerprints", selected)
                                        .putBoolean("all_keys", false).apply();
                                allKeys.setChecked(false);
                                // Reconnect explicitly so revoked selections take effect immediately.
                                if (RemoteAgentService.isRunning()) {
                                    stopService(new Intent(this, RemoteAgentService.class));
                                    message(R.string.remote_agent_reconnect);
                                }
                            }).setNeutralButton(R.string.remote_agent_all_keys, (dialog, which) ->
                                    allKeys.setChecked(true))
                            .setNegativeButton(android.R.string.cancel, null).show();
                });
            } catch (Exception e) {
                RemoteAgentDiagnostics.error("Reading local signing keys failed", e);
                runOnUiThread(() -> message(R.string.remote_agent_no_keys));
            }
        }, "signing-key-list").start();
    }

    private void connect() {
        if (RemoteAgentService.isRunning()) { message(R.string.remote_agent_reconnect); return; }
        String hostValue = hostname.getText().toString().trim();
        String controlValue = control.getText().toString().trim();
        String peersValue = allNodes.isChecked() ? "" : peers.getText().toString().trim();
        if (peersValue.isEmpty()) allNodes.setChecked(true);
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

    private void choosePassphraseKey() {
        if (!RemoteAgentService.isRunning()) { message(R.string.remote_agent_password_connect_first); return; }
        new Thread(() -> {
            try {
                List<RemoteSigningKey> keys = RemoteAgentConfig.selectedKeys(this, new RemoteSigningRepository(this));
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    if (!RemoteAgentService.isRunning()) { message(R.string.remote_agent_password_connect_first); return; }
                    if (keys.isEmpty()) { message(R.string.remote_agent_no_keys); return; }
                    CharSequence[] labels = new CharSequence[keys.size()];
                    for (int i = 0; i < keys.size(); i++) {
                        RemoteSigningKey key = keys.get(i);
                        labels[i] = key.userId + "\n" + key.algorithmName + "\n" + key.fingerprint
                                + (RemoteAgentService.hasPrefilledPassphrase(key.fingerprint)
                                ? "\n" + getString(R.string.remote_agent_password_prefilled) : "");
                    }
                    new AlertDialog.Builder(this).setTitle(R.string.remote_agent_prefill_password)
                            .setItems(labels, (dialog, position) -> editPassphrase(keys.get(position)))
                            .setNegativeButton(android.R.string.cancel, null).show();
                });
            } catch (Exception failure) {
                RemoteAgentDiagnostics.error("Reading signing keys for local prefill failed", failure);
                runOnUiThread(() -> message(R.string.remote_agent_no_keys));
            }
        }, "signing-passphrase-keys").start();
    }

    private void editPassphrase(RemoteSigningKey key) {
        if (passphraseDialog != null) passphraseDialog.dismiss();
        Object session = RemoteAgentService.passphraseSession();
        if (session == null) { message(R.string.remote_agent_password_connect_first); return; }
        EditText password = new EditText(this);
        password.setHint(R.string.remote_agent_key_password);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setSingleLine(true);
        password.setSaveEnabled(false);
        if (Build.VERSION.SDK_INT >= 26) {
            password.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        }
        char[] prefilled = RemoteAgentService.prefilledPassphrase(key.fingerprint);
        if (prefilled != null) {
            try { password.setText(prefilled, 0, prefilled.length); }
            finally { Arrays.fill(prefilled, '\0'); }
        }
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle(R.string.remote_agent_prefill_password)
                .setMessage(key.userId + "\n" + key.fingerprint + "\n\n"
                        + getString(R.string.remote_agent_password_prefill_details))
                .setView(password)
                .setPositiveButton(android.R.string.ok, (window, which) -> {
                    char[] value = new char[password.length()];
                    password.getText().getChars(0, value.length, value, 0);
                    password.getText().clear();
                    boolean saved = RemoteAgentService.setPrefilledPassphrase(session, key.fingerprint, value);
                    message(saved ? R.string.remote_agent_password_saved : R.string.remote_agent_password_connect_first);
                }).setNeutralButton(R.string.remote_agent_clear_password, (window, which) ->
                        RemoteAgentService.setPrefilledPassphrase(session, key.fingerprint, new char[0]))
                .setNegativeButton(android.R.string.cancel, null).create();
        passphraseDialog = dialog;
        passphraseSession = session;
        dialog.setOnDismissListener(window -> {
            password.getText().clear();
            if (passphraseDialog == dialog) {
                passphraseDialog = null;
                passphraseSession = null;
            }
        });
        dialog.show();
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setFilterTouchesWhenObscured(true);
    }

    private void refreshStatus() {
        if (passphraseDialog != null && !RemoteAgentService.isPassphraseSession(passphraseSession)) {
            passphraseDialog.dismiss();
        }
        RemoteAgentStatus snapshot = RemoteAgentService.status();
        if (snapshot != shownStatus) {
            shownStatus = snapshot;
            String text = statusText(snapshot);
            if (!TextUtils.equals(status.getText(), text)) status.setText(text);
            loginURL = snapshot.loginUrl;
            boolean canLogin = loginURL != null;
            if (login.isEnabled() != canLogin) login.setEnabled(canLogin);
        }
        long expiry = RemoteAgentService.bridgeExpiry();
        long visibleExpiry = expiry > System.currentTimeMillis() / 1000 ? expiry : 0;
        if (visibleExpiry != shownBridgeExpiry) {
            shownBridgeExpiry = visibleExpiry;
            if (visibleExpiry > 0) {
                bridgeStatus.setText(getString(R.string.remote_bridge_active,
                        java.text.DateFormat.getDateTimeInstance().format(new java.util.Date(visibleExpiry * 1000))));
            } else bridgeStatus.setText(R.string.remote_bridge_inactive);
        }
    }

    private String statusText(RemoteAgentStatus snapshot) {
        String text;
        if (snapshot.message != null) text = snapshot.message;
        else {
            text = getString(R.string.remote_agent_status_summary, snapshot.backendState,
                    snapshot.addresses.isEmpty() ? getString(R.string.remote_agent_status_no_address) : snapshot.addresses);
            if (!snapshot.health.isEmpty()) text += "\n" + getString(R.string.remote_agent_status_health, snapshot.health);
        }
        // Keep this bound even if translated labels change or malformed state reaches this view.
        return text.length() <= 1536 ? text : text.substring(0, 1535) + "…";
    }

    private void openDiagnosticLog() {
        RemoteAgentStatus snapshot = RemoteAgentService.status();
        RemoteAgentDiagnostics.info("Tailscale status snapshot: " + statusText(snapshot));
        RemoteAgentDiagnostics.open(this);
    }

    private void pairBridge() {
        if (!RemoteAgentService.isRunning()) { message(R.string.remote_bridge_create_failed); return; }
        bridgePair.setEnabled(false);
        RemoteAgentService.createBridgeTicket((ticket, error) -> runOnUiThread(() -> {
            if (isFinishing() || isDestroyed()) return;
            bridgePair.setEnabled(true);
            if (ticket == null) {
                Toast.makeText(this, error == null ? getString(R.string.remote_bridge_create_failed) : error,
                        Toast.LENGTH_LONG).show();
                return;
            }
            if (!RemoteAgentService.isCurrentBridgeTicket(ticket)) {
                message(R.string.remote_bridge_inactive);
                return;
            }
            TextView text = new TextView(this);
            int padding = (int) (20 * getResources().getDisplayMetrics().density);
            text.setPadding(padding, padding, padding, padding);
            text.setText(getString(R.string.remote_bridge_ticket_details) + "\n\n" + ticket);
            text.setTextIsSelectable(true);
            ScrollView scroll = new ScrollView(this);
            scroll.addView(text);
            AlertDialog dialog = new AlertDialog.Builder(this).setTitle(R.string.remote_bridge_pair)
                    .setView(scroll).setPositiveButton(R.string.remote_bridge_copy, (window, which) -> {
                        if (!RemoteAgentService.isCurrentBridgeTicket(ticket)) {
                            message(R.string.remote_bridge_inactive);
                            return;
                        }
                        ClipData clip = ClipData.newPlainText("gpg-bridge pairing", ticket);
                        PersistableBundle extras = new PersistableBundle();
                        extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
                        clip.getDescription().setExtras(extras);
                        getSystemService(ClipboardManager.class).setPrimaryClip(clip);
                    }).setNegativeButton(android.R.string.cancel, null).create();
            dialog.setOnDismissListener(window -> text.setText(""));
            dialog.show();
            dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }));
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (requestCode == 17373) {
            if (grants.length > 0 && grants[0] == PackageManager.PERMISSION_GRANTED) connect();
            else message(R.string.remote_agent_notifications_required);
        }
    }

    private void message(int resource) { Toast.makeText(this, resource, Toast.LENGTH_LONG).show(); }
    @Override protected void onResume() { super.onResume(); handler.removeCallbacks(refresh); handler.post(refresh); }
    @Override protected void onPause() {
        handler.removeCallbacks(refresh);
        if (passphraseDialog != null) passphraseDialog.dismiss();
        super.onPause();
    }
    @Override protected void onDestroy() {
        if (passphraseDialog != null) passphraseDialog.dismiss();
        super.onDestroy();
    }
}
