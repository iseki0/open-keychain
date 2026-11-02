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
import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.remote.agent.AgentBackend;
import org.sufficientlysecure.keychain.remote.agent.AgentException;
import org.sufficientlysecure.keychain.remote.agent.AgentKey;
import org.sufficientlysecure.keychain.remote.agent.AssuanSession;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningKey;
import org.sufficientlysecure.keychain.remoteagent.crypto.RemoteSigningRepository;
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
    static volatile String lastStatus = "Disconnected";
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final ScheduledExecutorService statusPoller = Executors.newSingleThreadScheduledExecutor();
    private final Semaphore sessions = new Semaphore(4);
    private final Set<Connection> connections = ConcurrentHashMap.newKeySet();
    private volatile boolean stopping;
    private volatile Node node;
    private boolean started;
    private Set<String> selectedFingerprints;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private boolean networkCallbackRegistered;

    static SigningApproval approval(String id) { return id == null ? null : approvals.get(id); }
    static boolean isRunning() { return active != null; }

    static String status() {
        // The UI only reads a snapshot; native LocalClient calls must not block the main thread.
        return lastStatus;
    }

    @Override public void onCreate() {
        super.onCreate();
        active = this;
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
            lastStatus = "Connecting";
            selectedFingerprints = RemoteAgentConfig.fingerprints(this);
            workers.execute(this::listen);
        }
        return START_NOT_STICKY;
    }

    private void listen() {
        try {
            if (!networkCallbackRegistered) throw new IOException("Network monitor unavailable");
            SharedPreferences settings = RemoteAgentConfig.preferences(this);
            Node created = Tailagent.newNode(new java.io.File(getFilesDir(), "tailnet-agent").getAbsolutePath(),
                    settings.getString("hostname", "openkeychain"), settings.getString("control", ""), "",
                    RemoteAgentConfig.PORT, settings.getString("peers", ""));
            synchronized (this) {
                if (stopping) { created.close(); return; }
                node = created;
            }
            created.start();
            enqueueNetworkRefresh();
            statusPoller.scheduleWithFixedDelay(() -> {
                try {
                    String status = created.statusJSON();
                    if (!stopping && active == this) lastStatus = status;
                } catch (Exception ignored) {
                    // A concurrent shutdown leaves the latest snapshot intact.
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
                lastStatus = "Connection failed: " + failure.getClass().getSimpleName();
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
                        for (RemoteSigningKey key : repository.listKeys(selectedFingerprints)) {
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
        } catch (Exception ignored) {
            // Do not log requests, digests, passphrases, or native errors containing peer information.
        } finally {
            connections.remove(connection);
            close(connection);
            sessions.release();
        }
    }

    private RemoteSigningKey findKey(RemoteSigningRepository repository, AgentKey requested) throws Exception {
        for (RemoteSigningKey key : repository.listKeys(selectedFingerprints)) {
            if (key.keygrip.equalsIgnoreCase(requested.getKeygrip())) return key;
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
        if (networkCallbackRegistered) {
            try { connectivity.unregisterNetworkCallback(networkCallback); }
            catch (RuntimeException ignored) {}
            networkCallbackRegistered = false;
        }
        statusPoller.shutdownNow();
        for (SigningApproval approval : approvals.values()) approval.deny();
        if (active == this && !lastStatus.startsWith("Connection failed:")) lastStatus = "Disconnecting";
        // tsnet shutdown can wait for Go goroutines and sockets. Keep it off Android's main
        // thread and retain the active marker until the node has released its state directory.
        new Thread(() -> {
            try {
                for (Connection connection : connections) close(connection);
                Node current = node;
                if (current != null) { try { current.close(); } catch (Exception ignored) {} }
            } finally {
                workers.shutdownNow();
                awaitTermination(workers);
                awaitTermination(statusPoller);
                if (active == this) {
                    if (!lastStatus.startsWith("Connection failed:")) lastStatus = "Disconnected";
                    active = null;
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
