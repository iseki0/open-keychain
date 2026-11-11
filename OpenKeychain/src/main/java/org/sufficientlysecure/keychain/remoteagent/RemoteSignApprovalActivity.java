package org.sufficientlysecure.keychain.remoteagent;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.Arrays;
import org.sufficientlysecure.keychain.R;

/** Only an immutable, app-created notification can open an existing in-memory request. */
public final class RemoteSignApprovalActivity extends Activity {
    private SigningApproval request;
    private EditText password;
    private boolean submitted;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setTitle(R.string.remote_agent_sign_request);
        request = RemoteAgentService.approval(getIntent().getStringExtra("request"));
        if (request == null || !request.claim()) {
            // A second tap must not cancel or wipe an approval already being consumed by the signer.
            request = null;
            finish();
            return;
        }
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
        TextView details = new TextView(this);
        details.setText(getString(R.string.remote_agent_approval_details, request.peer,
                request.key.userId, request.key.fingerprint, request.digestHex(), request.hashName()));
        details.setTextIsSelectable(true);
        content.addView(details);
        if (request.contentPreview != null) {
            TextView original = new TextView(this);
            original.setText(getString(R.string.remote_bridge_content, request.contentPreview));
            original.setTextIsSelectable(true);
            content.addView(original);
        }
        password = new EditText(this);
        password.setHint(R.string.remote_agent_key_password);
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setSaveEnabled(false);
        if (Build.VERSION.SDK_INT >= 26) {
            password.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        }
        char[] prefilled = RemoteAgentService.approvalPassphrase(this, request.key.fingerprint);
        if (prefilled != null) {
            try { password.setText(prefilled, 0, prefilled.length); }
            finally { Arrays.fill(prefilled, '\0'); }
        }
        content.addView(password);
        Button approve = new Button(this);
        approve.setText(R.string.remote_agent_approve);
        approve.setFilterTouchesWhenObscured(true);
        approve.setOnClickListener(view -> {
            char[] value = new char[password.length()];
            password.getText().getChars(0, value.length, value, 0);
            password.getText().clear();
            submitted = true;
            request.approve(value);
            finish();
        });
        content.addView(approve);
        Button deny = new Button(this);
        deny.setText(R.string.remote_agent_deny);
        deny.setOnClickListener(view -> finish());
        content.addView(deny);
        request.answer.whenComplete((answer, failure) -> runOnUiThread(() -> {
            password.getText().clear();
            if (!isFinishing() && !isDestroyed()) finish();
        }));
    }

    @Override protected void onDestroy() {
        if (password != null) password.getText().clear();
        if (request != null && !submitted) request.deny();
        super.onDestroy();
    }
}
