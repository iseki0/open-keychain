package org.sufficientlysecure.keychain.remoteagent;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.util.Map;
import org.junit.Test;

public class SigningPassphraseCacheTest {
    private static final String FIRST = "1111111111111111111111111111111111111111";
    private static final String SECOND = "2222222222222222222222222222222222222222";

    @Test public void cacheConsumesInputAndReturnsIndependentCopiesForTheExactKey() {
        SigningPassphraseCache cache = new SigningPassphraseCache();
        char[] input = "  密钥 passphrase  ".toCharArray();
        char[] expected = input.clone();
        cache.put(FIRST, input);
        assertArrayEquals(new char[input.length], input);
        assertTrue(cache.contains(FIRST));
        assertFalse(cache.contains(SECOND));
        assertNull(cache.copy(SECOND));
        char[] firstCopy = cache.copy(FIRST);
        assertArrayEquals(expected, firstCopy);
        java.util.Arrays.fill(firstCopy, '\0');
        assertArrayEquals(expected, cache.copy(FIRST));
    }

    @Test public void replacingAndRemovingAPassphraseWipesTheStoredArrays() throws Exception {
        SigningPassphraseCache cache = new SigningPassphraseCache();
        cache.put(FIRST, "old secret".toCharArray());
        char[] original = storedPassphrase(cache, FIRST);
        char[] replacement = "new secret".toCharArray();
        cache.put(FIRST, replacement);
        assertArrayEquals(new char[original.length], original);
        assertArrayEquals(new char[replacement.length], replacement);
        assertArrayEquals("new secret".toCharArray(), cache.copy(FIRST));
        char[] replaced = storedPassphrase(cache, FIRST);
        cache.put(FIRST, new char[0]);
        assertArrayEquals(new char[replaced.length], replaced);
        assertFalse(cache.contains(FIRST));
        assertNull(cache.copy(FIRST));
    }

    @Test public void removingOneKeyPreservesAnotherAndClearWipesAllRemainingSecrets() throws Exception {
        SigningPassphraseCache cache = new SigningPassphraseCache();
        cache.put(FIRST, "first secret".toCharArray());
        cache.put(SECOND, "second secret".toCharArray());
        char[] firstStored = storedPassphrase(cache, FIRST);
        char[] secondStored = storedPassphrase(cache, SECOND);
        cache.put(FIRST, new char[0]);
        assertArrayEquals(new char[firstStored.length], firstStored);
        assertArrayEquals("second secret".toCharArray(), cache.copy(SECOND));
        cache.clear();
        assertArrayEquals(new char[secondStored.length], secondStored);
        assertFalse(cache.contains(FIRST));
        assertFalse(cache.contains(SECOND));
        assertNull(cache.copy(SECOND));
        cache.clear();
    }

    // Hold a reference to the owned buffer so the test verifies erasure, not only map removal.
    private static char[] storedPassphrase(SigningPassphraseCache cache, String fingerprint)
            throws Exception {
        for (Field field : SigningPassphraseCache.class.getDeclaredFields()) {
            if (Map.class.isAssignableFrom(field.getType())) {
                field.setAccessible(true);
                Object value = ((Map<?, ?>) field.get(cache)).get(fingerprint);
                if (value instanceof char[]) return (char[]) value;
            }
        }
        throw new AssertionError("No owned passphrase buffer for " + fingerprint);
    }
}
