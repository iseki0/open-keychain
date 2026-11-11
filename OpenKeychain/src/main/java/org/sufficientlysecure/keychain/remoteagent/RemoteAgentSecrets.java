package org.sufficientlysecure.keychain.remoteagent;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Device-bound secrets for unattended remote signing: saved key passphrases and the
 * persistent gpg-bridge credentials. Values are encrypted with a non-exportable
 * AES-256-GCM key in the Android Keystore. The entry name is authenticated as AAD,
 * so ciphertexts cannot be swapped between keys. Uninstalling the app or clearing its
 * data destroys the Keystore key and therefore every stored value.
 */
final class RemoteAgentSecrets {
    private static final String FILE = "remote-signing-secrets";
    private static final String KEY_ALIAS = "openkeychain-remote-signing-secrets";
    private static final String PASSPHRASE_PREFIX = "passphrase:";
    private static final String BRIDGE_STATE = "bridge-state";
    private static final int IV_BYTES = 12;
    private static final int MAX_PASSPHRASE_CHARS = 4096;

    /** Supplies the wrapping key. Tests replace it because Robolectric has no Android Keystore. */
    interface KeySource { SecretKey key() throws GeneralSecurityException; }

    private static volatile KeySource keySource = RemoteAgentSecrets::androidKeystoreKey;

    private RemoteAgentSecrets() {}

    static void setKeySourceForTesting(KeySource source) {
        keySource = source == null ? RemoteAgentSecrets::androidKeystoreKey : source;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getApplicationContext().getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    // Saved passphrases ---------------------------------------------------------------

    /** Consumes passphrase. An empty value removes the saved passphrase. */
    static void savePassphrase(Context context, String fingerprint, char[] passphrase)
            throws GeneralSecurityException {
        byte[] encoded = null;
        try {
            String name = PASSPHRASE_PREFIX + fingerprint;
            if (passphrase.length == 0) {
                preferences(context).edit().remove(name).commit();
                return;
            }
            if (passphrase.length > MAX_PASSPHRASE_CHARS) throw new GeneralSecurityException("Passphrase too long");
            encoded = encode(passphrase);
            String sealed = seal(name, encoded);
            if (!preferences(context).edit().putString(name, sealed).commit()) {
                throw new GeneralSecurityException("Saving the passphrase failed");
            }
        } finally {
            Arrays.fill(passphrase, '\0');
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
        }
    }

    /** Returns a fresh copy for the caller to wipe, or null if none is saved or it cannot be read. */
    static char[] passphrase(Context context, String fingerprint) {
        String name = PASSPHRASE_PREFIX + fingerprint;
        String sealed = preferences(context).getString(name, null);
        if (sealed == null) return null;
        byte[] plain = null;
        try {
            plain = open(name, sealed);
            return decode(plain);
        } catch (GeneralSecurityException | CharacterCodingException | IllegalArgumentException e) {
            // A restored or corrupted entry cannot be decrypted with this device's key.
            RemoteAgentDiagnostics.error("A saved passphrase could not be decrypted and was removed", e);
            preferences(context).edit().remove(name).apply();
            return null;
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    static boolean hasPassphrase(Context context, String fingerprint) {
        return preferences(context).contains(PASSPHRASE_PREFIX + fingerprint);
    }

    static void clearPassphrases(Context context) {
        SharedPreferences preferences = preferences(context);
        SharedPreferences.Editor editor = preferences.edit();
        for (String name : preferences.getAll().keySet()) {
            if (name.startsWith(PASSPHRASE_PREFIX)) editor.remove(name);
        }
        editor.commit();
    }

    // Persistent gpg-bridge credentials ----------------------------------------------

    static void saveBridgeState(Context context, String state) throws GeneralSecurityException {
        byte[] plain = state.getBytes(StandardCharsets.UTF_8);
        try {
            if (!preferences(context).edit().putString(BRIDGE_STATE, seal(BRIDGE_STATE, plain)).commit()) {
                throw new GeneralSecurityException("Saving the gpg-bridge session failed");
            }
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Returns null if no session is saved. Undecryptable state is removed. */
    static String bridgeState(Context context) {
        String sealed = preferences(context).getString(BRIDGE_STATE, null);
        if (sealed == null) return null;
        byte[] plain = null;
        try {
            plain = open(BRIDGE_STATE, sealed);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            RemoteAgentDiagnostics.error("The saved gpg-bridge session could not be decrypted and was removed", e);
            clearBridgeState(context);
            return null;
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    static boolean hasBridgeState(Context context) {
        return preferences(context).contains(BRIDGE_STATE);
    }

    static void clearBridgeState(Context context) {
        preferences(context).edit().remove(BRIDGE_STATE).commit();
    }

    // Encryption -------------------------------------------------------------------------

    private static String seal(String name, byte[] plain) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySource.key());
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_BYTES) throw new GeneralSecurityException("Unexpected IV");
        byte[] encrypted = cipher.doFinal(plain);
        byte[] result = new byte[1 + iv.length + encrypted.length];
        result[0] = 1;
        System.arraycopy(iv, 0, result, 1, iv.length);
        System.arraycopy(encrypted, 0, result, 1 + iv.length, encrypted.length);
        return Base64.encodeToString(result, Base64.NO_WRAP);
    }

    private static byte[] open(String name, String sealed) throws GeneralSecurityException {
        byte[] data = Base64.decode(sealed, Base64.NO_WRAP);
        if (data.length < 1 + IV_BYTES + 16 || data[0] != 1) throw new GeneralSecurityException("Invalid entry");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySource.key(), new GCMParameterSpec(128, data, 1, IV_BYTES));
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(data, 1 + IV_BYTES, data.length - 1 - IV_BYTES);
    }

    private static synchronized SecretKey androidKeystoreKey() throws GeneralSecurityException {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            KeyStore.Entry entry = store.getEntry(KEY_ALIAS, null);
            if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            // No user-authentication requirement: unattended signing must work while the
            // phone is locked, including after a reboot once the user has unlocked it once.
            generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build());
            return generator.generateKey();
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException("Android Keystore unavailable", e);
        }
    }

    private static byte[] encode(char[] value) throws GeneralSecurityException {
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            byte[] result = new byte[buffer.remaining()];
            buffer.get(result);
            if (buffer.hasArray()) Arrays.fill(buffer.array(), (byte) 0);
            return result;
        } catch (CharacterCodingException e) {
            throw new GeneralSecurityException("Passphrase is not valid Unicode", e);
        }
    }

    private static char[] decode(byte[] value) throws CharacterCodingException {
        CharBuffer buffer = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value));
        char[] result = new char[buffer.remaining()];
        buffer.get(result);
        if (buffer.hasArray()) Arrays.fill(buffer.array(), '\0');
        return result;
    }
}
