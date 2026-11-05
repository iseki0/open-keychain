package org.sufficientlysecure.keychain.remoteagent;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningRepository;

/** Local opt-in configuration. Neither passwords nor Tailscale auth keys are stored here. */
final class RemoteAgentConfig {
    static final int PORT = 17373;
    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("remote-signing", Context.MODE_PRIVATE);
    }
    static Set<String> fingerprints(Context context) {
        return Collections.unmodifiableSet(new HashSet<>(preferences(context)
                .getStringSet("fingerprints", Collections.emptySet())));
    }
    static boolean allKeys(Context context) { return preferences(context).getBoolean("all_keys", false); }

    static List<RemoteSigningKey> selectedKeys(Context context, RemoteSigningRepository repository) throws Exception {
        return allKeys(context) ? repository.listAvailableKeys() : repository.listKeys(fingerprints(context));
    }

    static Set<String> effectiveFingerprints(Context context, RemoteSigningRepository repository) throws Exception {
        if (!allKeys(context)) return fingerprints(context);
        Set<String> result = new HashSet<>();
        for (RemoteSigningKey key : repository.listAvailableKeys()) result.add(key.fingerprint);
        return result;
    }
}
