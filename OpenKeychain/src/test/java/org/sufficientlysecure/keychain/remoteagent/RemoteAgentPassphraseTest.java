package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import android.app.Application;
import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ServiceController;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 28)
public class RemoteAgentPassphraseTest {
    private static final String KEY = "1111111111111111111111111111111111111111";
    private RemoteAgentService service;
    private ServiceController<RemoteAgentService> controller;

    @Before public void resetService() throws Exception {
        setActive(null);
        service = new RemoteAgentService();
    }

    @After public void closeService() throws Exception {
        RemoteAgentService.clearPrefilledPassphrases();
        setActive(null);
        if (controller != null) controller.destroy();
        for (String name : new String[] {"workers", "statusPoller", "bridgeControl"}) {
            Field field = RemoteAgentService.class.getDeclaredField(name);
            field.setAccessible(true);
            ExecutorService executor = (ExecutorService) field.get(service);
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS));
        }
        setActive(null);
        RemoteAgentDiagnostics.clear();
    }

    @Test public void disconnectedAndStoppingServicesConsumeInputsWithoutRetainingThem() throws Exception {
        char[] disconnected = "do not keep".toCharArray();
        assertFalse(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, disconnected));
        assertArrayEquals(new char[disconnected.length], disconnected);
        assertNull(RemoteAgentService.passphraseSession());
        assertFalse(RemoteAgentService.isPassphraseSession(null));
        assertNull(RemoteAgentService.prefilledPassphrase(KEY));
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));

        setActive(service);
        Object session = RemoteAgentService.passphraseSession();
        assertTrue(RemoteAgentService.isPassphraseSession(session));
        Field stopping = RemoteAgentService.class.getDeclaredField("stopping");
        stopping.setAccessible(true);
        stopping.setBoolean(service, true);
        char[] stopped = "also discard".toCharArray();
        assertFalse(RemoteAgentService.setPrefilledPassphrase(session, KEY, stopped));
        assertArrayEquals(new char[stopped.length], stopped);
        assertNull(RemoteAgentService.passphraseSession());
        assertFalse(RemoteAgentService.isPassphraseSession(session));
        assertNull(RemoteAgentService.prefilledPassphrase(KEY));
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
    }

    @Test public void aDialogFromAnOldSessionCannotWriteIntoAReconnectedService() throws Exception {
        RemoteAgentService oldService = service;
        setActive(oldService);
        Object oldSession = RemoteAgentService.passphraseSession();
        assertTrue(RemoteAgentService.setPrefilledPassphrase(oldSession, KEY, "old connection".toCharArray()));
        service = new RemoteAgentService();
        setActive(service);
        assertNotSame(oldSession, RemoteAgentService.passphraseSession());
        assertFalse(RemoteAgentService.isPassphraseSession(oldSession));
        char[] staleInput = "stale dialog input".toCharArray();
        assertFalse(RemoteAgentService.setPrefilledPassphrase(oldSession, KEY, staleInput));
        assertArrayEquals(new char[staleInput.length], staleInput);
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
        assertNull(RemoteAgentService.prefilledPassphrase(KEY));
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY,
                "new connection".toCharArray()));
        assertArrayEquals("new connection".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
        Field cache = RemoteAgentService.class.getDeclaredField("passphrases");
        cache.setAccessible(true);
        ((SigningPassphraseCache) cache.get(oldService)).clear();
        for (String name : new String[] {"workers", "statusPoller", "bridgeControl"}) {
            Field field = RemoteAgentService.class.getDeclaredField(name);
            field.setAccessible(true);
            ((ExecutorService) field.get(oldService)).shutdownNow();
        }
    }

    @Test public void runningServicePrefillsUsingCopiesAndSupportsExplicitRemovalAndClear() throws Exception {
        setActive(service);
        char[] input = "local secret".toCharArray();
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, input));
        assertArrayEquals(new char[input.length], input);
        assertTrue(RemoteAgentService.hasPrefilledPassphrase(KEY));
        char[] copy = RemoteAgentService.prefilledPassphrase(KEY);
        assertArrayEquals("local secret".toCharArray(), copy);
        java.util.Arrays.fill(copy, '\0');
        assertArrayEquals("local secret".toCharArray(), RemoteAgentService.prefilledPassphrase(KEY));
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, new char[0]));
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
        assertNull(RemoteAgentService.prefilledPassphrase(KEY));
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "another secret".toCharArray()));
        RemoteAgentService.clearPrefilledPassphrases();
        assertFalse(RemoteAgentService.hasPrefilledPassphrase(KEY));
        assertNull(RemoteAgentService.prefilledPassphrase(KEY));
    }

    @Test public void destroyingTheServiceClearsItsOwnedCacheBeforeReturning() throws Exception {
        controller = Robolectric.buildService(RemoteAgentService.class).create();
        service = controller.get();
        assertTrue(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "ephemeral".toCharArray()));
        Field field = RemoteAgentService.class.getDeclaredField("passphrases");
        field.setAccessible(true);
        SigningPassphraseCache ownedCache = (SigningPassphraseCache) field.get(service);
        controller.destroy();
        controller = null;
        assertFalse(ownedCache.contains(KEY));
        assertNull(ownedCache.copy(KEY));
        assertFalse(RemoteAgentService.setPrefilledPassphrase(RemoteAgentService.passphraseSession(), KEY, "late input".toCharArray()));
    }

    private static void setActive(RemoteAgentService service) throws Exception {
        Field field = RemoteAgentService.class.getDeclaredField("active");
        field.setAccessible(true);
        field.set(null, service);
    }
}
