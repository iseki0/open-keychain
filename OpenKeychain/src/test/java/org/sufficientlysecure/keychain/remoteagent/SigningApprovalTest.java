package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public class SigningApprovalTest {
    private SigningApproval request() {
        return new SigningApproval("peer", null, 8, new byte[32]);
    }

    @Test public void onlyOneActivityCanClaimARequest() throws Exception {
        SigningApproval request = request();
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        Runnable claim = () -> {
            try { start.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
            if (request.claim()) winners.incrementAndGet();
        };
        Thread first = new Thread(claim);
        Thread second = new Thread(claim);
        first.start();
        second.start();
        start.countDown();
        first.join();
        second.join();
        assertEquals(1, winners.get());
    }

    @Test public void expiredRequestCannotBeClaimedOrReceiveAPassword() {
        SigningApproval request = request();
        request.deny();
        assertFalse(request.claim());
        char[] password = "discard this".toCharArray();
        request.approve(password);
        assertNull(request.answer.getNow(null));
        assertArrayEquals(new char[password.length], password);
    }

    @Test public void duplicateApprovalWipesOnlyTheRejectedPassword() {
        SigningApproval request = request();
        char[] first = "first".toCharArray();
        char[] duplicate = "duplicate".toCharArray();
        request.approve(first);
        request.approve(duplicate);
        assertSame(first, request.answer.getNow(null));
        assertArrayEquals("first".toCharArray(), first);
        assertArrayEquals(new char[duplicate.length], duplicate);
    }

    @Test public void disposingAnApprovedRequestWipesItsPassword() {
        SigningApproval request = request();
        char[] password = "first".toCharArray();
        request.approve(password);
        request.deny();
        assertArrayEquals(new char[password.length], password);
    }
}
