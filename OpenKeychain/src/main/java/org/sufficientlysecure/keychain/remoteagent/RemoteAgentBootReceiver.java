package org.sufficientlysecure.keychain.remoteagent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import androidx.core.app.NotificationManagerCompat;

/** Starts the opt-in remote signing service after boot or after this app is updated. */
public final class RemoteAgentBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) return;
        if (!RemoteAgentConfig.startOnBoot(context) || RemoteAgentService.isRunning()) return;
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            RemoteAgentDiagnostics.warn("Automatic start skipped: notifications are disabled");
            return;
        }
        RemoteAgentDiagnostics.info("Starting remote signing automatically (" + action + ")");
        Intent service = new Intent(context, RemoteAgentService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(service);
            else context.startService(service);
        } catch (RuntimeException failure) {
            RemoteAgentDiagnostics.error("Automatic start of remote signing failed", failure);
        }
    }
}
