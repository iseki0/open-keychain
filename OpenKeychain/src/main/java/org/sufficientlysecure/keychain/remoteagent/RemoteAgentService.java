package org.sufficientlysecure.keychain.remoteagent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.os.Build;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.remote.agent.AgentBackend;
import org.sufficientlysecure.keychain.remote.agent.AgentException;
import org.sufficientlysecure.keychain.remote.agent.AgentKey;
import org.sufficientlysecure.keychain.remote.agent.AssuanSession;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningRepository;
import org.sufficientlysecure.keychain.remoteagent.crypto.BridgeSignature;
import tailagent.BridgeBackend;
import tailagent.Connection;
import tailagent.Node;
import tailagent.Tailagent;

/** A manually started foreground service. Its only network listener lives inside tsnet. */
public final class RemoteAgentService extends Service {
    private static final String CHANNEL = "remote-signing";
    private static final int SERVICE_NOTIFICATION = 17373;
    private static final AtomicInteger notificationIds = new AtomicInteger(18000);
    private static final ConcurrentHashMap<String, SigningApproval> approvals = new ConcurrentHashMap<>();
    private static volatile RemoteAgentService active;
    private static volatile RemoteAgentStatus currentStatus = RemoteAgentStatus.initial();
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final ScheduledExecutorService statusPoller = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService bridgeControl = Executors.newSingleThreadExecutor();
    private final AtomicLong bridgeEpoch = new AtomicLong();
    private volatile String bridgeTicket = "";
    private volatile long bridgeExpires;
    private final Semaphore sessions = new Semaphore(4);
    private final Set<Connection> connections = ConcurrentHashMap.newKeySet();
    private volatile boolean stopping;
    private volatile Node node;
    private boolean started;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private boolean networkCallbackRegistered;
    private String lastBackendState = "";
    private String lastStatusFailure = "";
    private String lastNetwork = "";

    static SigningApproval approval(String id) { return id == null ? null : approvals.get(id); }
    static boolean isRunning() { return active != null; }

    interface BridgeTicketCallback { void complete(String ticket, String error); }

    static long bridgeExpiry() {
        RemoteAgentService service = active;
        return service == null || service.stopping ? 0 : service.bridgeExpires;
    }

    static boolean isCurrentBridgeTicket(String ticket) {
        RemoteAgentService service = active;
        return service != null && !service.stopping && ticket != null
                && System.currentTimeMillis() / 1000 < service.bridgeExpires
                && ticket.equals(service.bridgeTicket);
    }

    static void createBridgeTicket(BridgeTicketCallback callback) {
        RemoteAgentService service = active;
        if (service == null || service.stopping) { callback.complete(null, null); return; }
        try { service.bridgeControl.execute(() -> service.startBridge(callback)); }
        catch (RejectedExecutionException ignored) { callback.complete(null, null); }
    }

    static void revokeBridge() {
        RemoteAgentService service = active;
        if (service == null) return;
        RemoteAgentDiagnostics.info("Revoking gpg-bridge session");
        service.bridgeEpoch.incrementAndGet();
        service.bridgeTicket = "";
        service.bridgeExpires = 0;
        for (SigningApproval approval : approvals.values()) {
            if (approval.contentPreview != null) approval.deny();
        }
        try { service.bridgeControl.execute(() -> {
            Node current = service.node;
            if (current != null) { try { current.stopBridge(); } catch (Exception ignored) {} }
        }); } catch (RejectedExecutionException ignored) {}
    }

    private void startBridge(BridgeTicketCallback callback) {
        try {
            Node current = node;
            if (stopping || current == null) throw new IOException("Not connected");
            if (!bridgeTicket.isEmpty() && System.currentTimeMillis() / 1000 < bridgeExpires) {
                callback.complete(bridgeTicket, null);
                return;
            }
            RemoteSigningRepository repository = new RemoteSigningRepository(this);
            if (RemoteAgentConfig.selectedKeys(this, repository).isEmpty()) {
                callback.complete(null, getString(R.string.remote_agent_no_keys));
                return;
            }
            long epoch = bridgeEpoch.incrementAndGet();
            bridgeTicket = "";
            bridgeExpires = 0;
            BridgeBackend backend = new BridgeBackend() {
                @Override public String infoJSON() throws Exception {
                    if (stopping || bridgeEpoch.get() != epoch) throw new IOException("Session revoked");
                    RemoteSigningRepository keys = new RemoteSigningRepository(RemoteAgentService.this);
                    return keys.bridgeKeysJson(RemoteAgentConfig.effectiveFingerprints(RemoteAgentService.this, keys));
                }
                @Override public String sign(String fingerprint, byte[] data, String peerID,
                        String peerName) throws Exception {
                    return approveBridgeSign(epoch, fingerprint, data, peerName + " (" + peerID + ")");
                }
            };
            String ticket = current.startBridge(backend, 8 * 60 * 60);
            if (stopping || bridgeEpoch.get() != epoch) {
                current.stopBridge();
                throw new IOException("Session revoked");
            }
            byte[] encoded = android.util.Base64.decode(ticket.substring("gpgbridge:v1:".length()),
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
            long expires = new JSONObject(new String(encoded, java.nio.charset.StandardCharsets.UTF_8))
                    .getLong("expires");
            bridgeExpires = expires;
            bridgeTicket = ticket;
            RemoteAgentDiagnostics.info("gpg-bridge ready: tailnet TCP 17389, expires=" + expires);
            callback.complete(ticket, null);
        } catch (Exception e) {
            RemoteAgentDiagnostics.error("Starting gpg-bridge failed", e);
            bridgeEpoch.incrementAndGet();
            bridgeTicket = "";
            bridgeExpires = 0;
            Node current = node;
            if (current != null) { try { current.stopBridge(); } catch (Exception ignored) {} }
            callback.complete(null, getString(R.string.remote_bridge_create_failed));
        }
    }

    private void requireBridge(long epoch) throws IOException {
        if (stopping || bridgeEpoch.get() != epoch || bridgeTicket.isEmpty()
                || System.currentTimeMillis() / 1000 >= bridgeExpires)
            throw new IOException("Bridge session expired or revoked");
    }

    private RemoteSigningKey bridgeKey(RemoteSigningRepository repository, String fingerprint) throws Exception {
        for (RemoteSigningKey key : RemoteAgentConfig.selectedKeys(this, repository)) {
            if (key.fingerprint.equals(fingerprint)) return key;
        }
        throw new IOException("Signing key unavailable");
    }

    private String approveBridgeSign(long epoch, String fingerprint, byte[] data, String peer) throws Exception {
        requireBridge(epoch);
        if (data == null || data.length == 0 || data.length > 1024 * 1024)
            throw new IOException("Invalid signing data");
        RemoteSigningRepository repository = new RemoteSigningRepository(this);
        RemoteSigningKey key = bridgeKey(repository, fingerprint);
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(data);
        SigningApproval request = new SigningApproval(peer, key, 8, digest,
                getString(R.string.remote_bridge_bytes, data.length) + "\n\n" + bridgePreview(data));
        int notificationId = notificationIds.incrementAndGet();
        approvals.put(request.id, request);
        RemoteAgentDiagnostics.info("gpg-bridge signing request: peer=" + peer + ", key="
                + fingerprint + ", bytes=" + data.length);
        char[] password = null;
        try {
            requireBridge(epoch);
            if (!NotificationManagerCompat.from(this).areNotificationsEnabled())
                throw new IOException("Local approval unavailable");
            Intent intent = new Intent(this, RemoteSignApprovalActivity.class).putExtra("request", request.id);
            getSystemService(NotificationManager.class).notify(notificationId,
                    notification(getString(R.string.remote_agent_sign_request), intent, notificationId)
                            .setAutoCancel(true).build());
            long remaining = Math.min(90, bridgeExpires - System.currentTimeMillis() / 1000);
            if (remaining <= 0) throw new IOException("Bridge session expired");
            password = request.answer.get(remaining, TimeUnit.SECONDS);
            if (password == null) throw new IOException("Signing denied");
            requireBridge(epoch);
            BridgeSignature signed = repository.signData(bridgeKey(repository, fingerprint), data, password);
            requireBridge(epoch);
            RemoteAgentDiagnostics.info("gpg-bridge signature completed: " + fingerprint);
            return new JSONObject().put("signature", signed.signature).put("status", signed.status).toString();
        } catch (Exception failure) {
            RemoteAgentDiagnostics.error("gpg-bridge signature rejected or failed", failure);
            throw failure;
        } finally {
            approvals.remove(request.id);
            request.deny();
            if (password != null) Arrays.fill(password, '\0');
            getSystemService(NotificationManager.class).cancel(notificationId);
        }
    }

    private String bridgePreview(byte[] data) {
        String text = new String(data, 0, Math.min(data.length, 32768), java.nio.charset.StandardCharsets.UTF_8);
        StringBuilder output = new StringBuilder();
        int index = 0;
        for (; index < text.length() && output.length() < 8192; index++) {
            char value = text.charAt(index);
            if ((Character.isISOControl(value) && value != '\n') || Character.getType(value) == Character.FORMAT)
                output.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) value));
            else output.append(value);
        }
        if (index < text.length() || data.length > 32768)
            output.append("\n").append(getString(R.string.remote_bridge_truncated));
        return output.toString();
    }

    static RemoteAgentStatus status() {
        // JSON parsing and native calls belong to the worker. The UI reads bounded fields only.
        return currentStatus;
    }

    private static void publishStatus(RemoteAgentStatus next) {
        if (!next.equals(currentStatus)) currentStatus = next;
    }

    @Override public void onCreate() {
        super.onCreate();
        active = this;
        RemoteAgentDiagnostics.info("Remote signing startup: Android " + Build.VERSION.RELEASE
                + " / API " + Build.VERSION.SDK_INT + ", build=" + Build.DISPLAY
                + ", package=" + getPackageName());
        connectivity = getSystemService(ConnectivityManager.class);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { enqueueNetworkRefresh(); }
            @Override public void onLost(Network network) { enqueueNetworkRefresh(); }
            @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                enqueueNetworkRefresh();
            }
            @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                enqueueNetworkRefresh();
            }
        };
        try {
            connectivity.registerDefaultNetworkCallback(networkCallback);
            networkCallbackRegistered = true;
        } catch (RuntimeException ignored) {
            RemoteAgentDiagnostics.error("Registering Android default-network callback failed", ignored);
            // listen() fails before joining a tailnet if connectivity monitoring is unavailable.
        }
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(CHANNEL,
                    getString(R.string.remote_agent_title), NotificationManager.IMPORTANCE_DEFAULT);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "stop".equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(SERVICE_NOTIFICATION, notification(getString(R.string.remote_agent_running),
                new Intent(this, RemoteAgentActivity.class), SERVICE_NOTIFICATION).setOngoing(true).build());
        if (!started) {
            started = true;
            publishStatus(RemoteAgentStatus.message("Connecting"));
            workers.execute(this::listen);
        }
        return START_NOT_STICKY;
    }

    private void listen() {
        try {
            if (!networkCallbackRegistered) throw new IOException("Network monitor unavailable");
            SharedPreferences settings = RemoteAgentConfig.preferences(this);
            String peers = settings.getString("peers", "");
            RemoteAgentDiagnostics.info("Node access: " + (peers.isEmpty() ? "all Tailscale nodes" : "selected NodeIDs")
                    + "; keys=" + (RemoteAgentConfig.allKeys(this) ? "all signing keys" : "selected fingerprints"));
            RemoteAgentDiagnostics.info("Creating embedded Tailscale node");
            Node created = Tailagent.newNode(new java.io.File(getFilesDir(), "tailnet-agent").getAbsolutePath(),
                    settings.getString("hostname", "openkeychain"), settings.getString("control", ""), "",
                    RemoteAgentConfig.PORT, settings.getString("peers", ""));
            synchronized (this) {
                if (stopping) { created.close(); return; }
                node = created;
            }
            RemoteAgentDiagnostics.info("Starting embedded Tailscale node and Assuan listener");
            created.start();
            drainNativeLogs();
            RemoteAgentDiagnostics.info("Embedded Tailscale started; Assuan tailnet TCP 17373 ready");
            enqueueNetworkRefresh();
            statusPoller.scheduleWithFixedDelay(() -> {
                try {
                    drainNativeLogs();
                    RemoteAgentStatus state = RemoteAgentStatus.parse(created.statusSummaryJSON());
                    synchronized (RemoteAgentService.this) {
                        if (stopping || active != RemoteAgentService.this) return;
                        publishStatus(state);
                    }
                    String backend = state.backendState;
                    if (!backend.equals(lastBackendState)) {
                        lastBackendState = backend;
                        RemoteAgentDiagnostics.info("Tailscale state=" + backend
                                + ", login URL available=" + (state.loginUrl != null));
                    }
                    lastStatusFailure = "";
                } catch (Exception failure) {
                    String summary = RemoteAgentDiagnostics.failure(failure);
                    synchronized (RemoteAgentService.this) {
                        if (stopping || active != RemoteAgentService.this) return;
                        publishStatus(RemoteAgentStatus.failure("Status unavailable: " + summary));
                    }
                    if (!stopping && !summary.equals(lastStatusFailure)) {
                        lastStatusFailure = summary;
                        RemoteAgentDiagnostics.error("Reading Tailscale status failed", failure);
                    }
                }
            }, 0, 2, TimeUnit.SECONDS);
            while (!stopping) {
                Connection connection = created.accept();
                if (!sessions.tryAcquire()) { connection.close(); continue; }
                connections.add(connection);
                if (stopping) { close(connection); sessions.release(); break; }
                workers.execute(() -> serve(connection));
            }
        } catch (Exception | LinkageError failure) {
            if (!stopping) {
                drainNativeLogs();
                RemoteAgentDiagnostics.error("Starting embedded Tailscale failed", failure);
                publishStatus(RemoteAgentStatus.failure("Connection failed: " + RemoteAgentDiagnostics.failure(failure)));
                stopSelf();
            }
        }
    }

    private void serve(Connection connection) {
        try {
            RemoteSigningRepository repository = new RemoteSigningRepository(this);
            AgentBackend backend = new AgentBackend() {
                @Override public List<AgentKey> getKeys() throws AgentException {
                    try {
                        List<AgentKey> result = new ArrayList<>();
                        for (RemoteSigningKey key : RemoteAgentConfig.selectedKeys(RemoteAgentService.this, repository)) {
                            if (key.keygrip != null && key.publicKeySExpression != null)
                                result.add(new AgentKey(key.keygrip, key.publicKeySExpression, key.fingerprint));
                        }
                        return result;
                    } catch (Exception e) { throw new AgentException(AgentException.NO_SECRET_KEY, "Key unavailable"); }
                }

                @Override public byte[] sign(AgentKey requested, int hashAlgorithm, byte[] digest,
                        String description) throws AgentException {
                    if (hashAlgorithm != 8 && hashAlgorithm != 9 && hashAlgorithm != 10) {
                        throw new AgentException(AgentException.NOT_SUPPORTED, "Unsupported signing digest");
                    }
                    try {
                        // Reload validity and selection for every signature, including after approval.
                        RemoteSigningKey key = findKey(repository, requested);
                        return approveAndSign(connection, repository, key, hashAlgorithm, digest);
                    } catch (AgentException e) { throw e; }
                    catch (Exception e) { throw new AgentException(AgentException.GENERAL, "Signing failed"); }
                }
            };
            InputStream input = new InputStream() {
                private byte[] pending = new byte[0];
                private int offset;
                @Override public int read() throws IOException {
                    if (offset == pending.length) {
                        try { pending = connection.readBytes(4096); offset = 0; }
                        catch (Exception e) { throw new IOException("Tailnet read failed", e); }
                        if (pending == null || pending.length == 0) return -1;
                    }
                    return pending[offset++] & 255;
                }
            };
            OutputStream output = new OutputStream() {
                @Override public void write(int value) throws IOException { write(new byte[] {(byte) value}); }
                @Override public void write(byte[] value, int offset, int length) throws IOException {
                    int done = 0;
                    try {
                        while (done < length) {
                            int count = (int) connection.writeBytes(Arrays.copyOfRange(value, offset + done, offset + length));
                            if (count <= 0) throw new IOException("Tailnet stream closed");
                            done += count;
                        }
                    } catch (Exception e) { throw new IOException("Tailnet write failed", e); }
                }
            };
            new AssuanSession(backend).serve(input, output);
        } catch (Exception failure) {
            if (!stopping) RemoteAgentDiagnostics.error("Assuan connection ended", failure);
        } finally {
            connections.remove(connection);
            close(connection);
            sessions.release();
        }
    }

    private RemoteSigningKey findKey(RemoteSigningRepository repository, AgentKey requested) throws Exception {
        for (RemoteSigningKey key : RemoteAgentConfig.selectedKeys(this, repository)) {
            if (key.keygrip != null && key.keygrip.equalsIgnoreCase(requested.getKeygrip())) return key;
        }
        throw new AgentException(AgentException.NO_SECRET_KEY, "Selected signing key unavailable");
    }

    private byte[] approveAndSign(Connection connection, RemoteSigningRepository repository,
            RemoteSigningKey key, int hashAlgorithm, byte[] digest) throws Exception {
        SigningApproval request = new SigningApproval(connection.getPeerName() + " (" + connection.getPeerId() + ")",
                key, hashAlgorithm, digest);
        int notificationId = notificationIds.incrementAndGet();
        approvals.put(request.id, request);
        char[] password = null;
        try {
            if (stopping || !NotificationManagerCompat.from(this).areNotificationsEnabled())
                throw new AgentException(AgentException.CANCELED, "Local approval unavailable");
            Intent approvalIntent = new Intent(this, RemoteSignApprovalActivity.class).putExtra("request", request.id);
            getSystemService(NotificationManager.class).notify(notificationId,
                    notification(getString(R.string.remote_agent_sign_request), approvalIntent, notificationId)
                            .setAutoCancel(true).build());
            password = request.answer.get(90, TimeUnit.SECONDS);
            if (password == null || stopping) throw new AgentException(AgentException.CANCELED, "Signing denied");
            RemoteSigningKey current = findKey(repository,
                    new AgentKey(key.keygrip, key.publicKeySExpression, key.fingerprint));
            return repository.sign(current, hashAlgorithm, digest, password);
        } catch (Exception failure) {
            RemoteAgentDiagnostics.error("Assuan signature rejected or failed", failure);
            throw failure;
        } finally {
            approvals.remove(request.id);
            request.deny();
            if (password != null) Arrays.fill(password, '\0');
            getSystemService(NotificationManager.class).cancel(notificationId);
        }
    }

    private NotificationCompat.Builder notification(String text, Intent intent, int id) {
        PendingIntent open = PendingIntent.getActivity(this, id, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, SERVICE_NOTIFICATION,
                new Intent(this, RemoteAgentService.class).setAction("stop"),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_lock_black_24dp)
                .setContentTitle(getString(R.string.remote_agent_title)).setContentText(text).setContentIntent(open)
                .addAction(0, getString(R.string.remote_agent_disconnect), stop);
    }

    private void close(Connection connection) { try { connection.close(); } catch (Exception ignored) {} }

    private void drainNativeLogs() {
        Node current = node;
        if (current == null) return;
        try {
            org.json.JSONArray lines = new org.json.JSONArray(current.drainLogsJSON());
            for (int index = 0; index < lines.length(); index++)
                RemoteAgentDiagnostics.info("Tailscale: " + lines.getString(index));
        } catch (Exception ignored) {
            // The final explicit error is recorded even if the native log buffer cannot be read.
        }
    }

    private void enqueueNetworkRefresh() {
        if (stopping) return;
        try {
            statusPoller.execute(() -> {
                Node current = node;
                if (stopping || current == null) return;
                try {
                    // Read the current default network when the task runs, rather than trusting
                    // a possibly stale onLost/onAvailable callback argument during handover.
                    Network network = connectivity.getActiveNetwork();
                    LinkProperties properties = network == null ? null : connectivity.getLinkProperties(network);
                    String interfaceName = properties == null ? "" : properties.getInterfaceName();
                    String gateway = "";
                    if (properties != null) {
                        for (RouteInfo route : properties.getRoutes()) {
                            java.net.InetAddress address = route.getGateway();
                            if (route.isDefaultRoute() && address != null && !address.isAnyLocalAddress()) {
                                gateway = address.getHostAddress();
                                if (address instanceof java.net.Inet4Address) break;
                            }
                        }
                    }
                    String snapshot = "interface=" + interfaceName + ", gateway=" + gateway;
                    if (!snapshot.equals(lastNetwork)) {
                        lastNetwork = snapshot;
                        RemoteAgentDiagnostics.info("Android default network: " + snapshot);
                    }
                    current.networkChanged(interfaceName == null ? "" : interfaceName, gateway);
                } catch (Exception ignored) {
                    // Shutdown or a simultaneous OS network transition can invalidate the snapshot.
                }
            });
        } catch (RejectedExecutionException ignored) {
            // A connectivity callback queued before unregister may race service shutdown.
        }
    }

    @Override public void onDestroy() {
        synchronized (this) { stopping = true; }
        RemoteAgentDiagnostics.info("Stopping remote signing and revoking active sessions");
        bridgeEpoch.incrementAndGet();
        bridgeTicket = "";
        bridgeExpires = 0;
        bridgeControl.shutdownNow();
        if (networkCallbackRegistered) {
            try { connectivity.unregisterNetworkCallback(networkCallback); }
            catch (RuntimeException ignored) {}
            networkCallbackRegistered = false;
        }
        statusPoller.shutdownNow();
        for (SigningApproval approval : approvals.values()) approval.deny();
        if (active == this && !currentStatus.failed) publishStatus(RemoteAgentStatus.message("Disconnecting"));
        // tsnet shutdown can wait for Go goroutines and sockets. Keep it off Android's main
        // thread and retain the active marker until the node has released its state directory.
        new Thread(() -> {
            try {
                for (Connection connection : connections) close(connection);
                drainNativeLogs();
                Node current = node;
                if (current != null) { try { current.close(); } catch (Exception ignored) {} }
            } finally {
                workers.shutdownNow();
                awaitTermination(workers);
                awaitTermination(statusPoller);
                awaitTermination(bridgeControl);
                if (active == this) {
                    if (!currentStatus.failed) publishStatus(RemoteAgentStatus.initial());
                    active = null;
                    RemoteAgentDiagnostics.info("Remote signing stopped");
                }
            }
        }, "tailnet-agent-close").start();
        stopForeground(true);
        super.onDestroy();
    }

    private static void awaitTermination(ExecutorService executor) {
        boolean interrupted = false;
        while (!executor.isTerminated()) {
            try { executor.awaitTermination(30, TimeUnit.SECONDS); }
            catch (InterruptedException ignored) { interrupted = true; }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
