package org.sufficientlysecure.keychain.remote.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * A deliberately signing-only subset of gpg-agent's Assuan interface.
 *
 * The caller must authenticate and authorize the transport before serving it.
 * One instance belongs to one connection and must not be used concurrently.
 * No request can export a secret, decrypt, change a key, or supply a passphrase.
 */
public final class AssuanSession {
    private static final Charset ASCII = Charset.forName("US-ASCII");
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int ERROR_SOURCE_AGENT = 4 << 24;
    private static final int MAX_LINE_BYTES = 1000;
    private static final int MAX_BACKEND_DATA = 64 * 1024;
    private static final int UNKNOWN_COMMAND = 275;
    private static final int UNKNOWN_OPTION = 174;
    private static final int FALSE = 256;
    private final AgentBackend backend;
    private String keygrip;
    private int hashAlgorithm;
    private byte[] digest;
    private String description = "";

    public AssuanSession(AgentBackend backend) {
        if (backend == null) { throw new NullPointerException("backend"); }
        this.backend = backend;
    }

    public void serve(InputStream input, OutputStream output) throws IOException {
        writeLine(output, "OK OpenKeychain remote signing agent");
        try {
            while (true) {
                final String line;
                try {
                    line = readLine(input);
                } catch (LineException e) {
                    error(output, AgentException.INVALID_VALUE, e.getMessage());
                    break;
                }
                if (line == null) { break; }
                if (line.isEmpty() || line.charAt(0) == '#') { continue; }
                int space = line.indexOf(' ');
                String command = (space < 0 ? line : line.substring(0, space)).toUpperCase(Locale.ROOT);
                String args = space < 0 ? "" : line.substring(space + 1).trim();
                try {
                    if ("BYE".equals(command)) {
                        writeLine(output, "OK closing connection");
                        break;
                    }
                    execute(command, args, output);
                } catch (AgentException e) {
                    error(output, e.getCode(), e.getMessage());
                } catch (RuntimeException e) {
                    // Never disclose exception text from a key store or a UI callback.
                    clearDigest();
                    error(output, AgentException.GENERAL, "Signing agent failed");
                }
            }
        } finally {
            reset();
        }
    }

    private void execute(String command, String args, OutputStream out)
            throws AgentException, IOException {
        if ("RESET".equals(command)) {
            requireEmpty(args);
            reset();
        } else if ("NOP".equals(command) || "UPDATESTARTUPTTY".equals(command)) {
            requireEmpty(args);
        } else if ("OPTION".equals(command)) {
            option(args);
        } else if ("GETINFO".equals(command)) {
            getInfo(args, out);
        } else if ("HAVEKEY".equals(command)) {
            haveKey(args, out);
        } else if ("KEYINFO".equals(command)) {
            keyInfo(args, out);
        } else if ("READKEY".equals(command)) {
            AgentKey key = findKey(parseKeygrip(args));
            data(out, key.getPublicKeySExpression());
        } else if ("SIGKEY".equals(command) || "SETKEY".equals(command)) {
            clearDigest();
            keygrip = null;
            String requested = parseKeygrip(args);
            findKey(requested);
            keygrip = requested;
        } else if ("SETKEYDESC".equals(command)) {
            description = decodeDescription(args);
        } else if ("SETHASH".equals(command)) {
            setHash(args);
        } else if ("PKSIGN".equals(command)) {
            sign(args, out);
        } else {
            throw new AgentException(UNKNOWN_COMMAND, "Unsupported signing-agent command");
        }
        writeLine(out, "OK");
    }

    private void option(String args) throws AgentException {
        int equals = args.indexOf('=');
        String name = equals < 0 ? args : args.substring(0, equals);
        // These options concern a desktop pinentry. Approval always happens on
        // the phone, even when a client requests loopback or cached pinentry.
        if (!("ttyname".equals(name) || "ttytype".equals(name) || "display".equals(name)
                || "xauthority".equals(name) || "lc-ctype".equals(name)
                || "lc-messages".equals(name) || "pinentry-mode".equals(name)
                || "allow-pinentry-notify".equals(name) || "allow-external-cache".equals(name)
                || "agent-awareness".equals(name) || "request-origin".equals(name)
                || "pretend-request-origin".equals(name))) {
            throw new AgentException(UNKNOWN_OPTION, "Unknown option");
        }
    }

    private void getInfo(String args, OutputStream out) throws AgentException, IOException {
        if ("version".equals(args)) {
            data(out, "2.4.7-openkeychain".getBytes(ASCII));
        } else if ("pid".equals(args)) {
            // This is a remote endpoint, not a killable local gpg-agent process.
            data(out, "0".getBytes(ASCII));
        } else if ("restricted".equals(args)) {
            // The endpoint is deliberately restricted: no decrypt/export/delete.
        } else if ("s2k_count".equals(args)) {
            data(out, "65536".getBytes(ASCII));
        } else if ("cmd_has_option HAVEKEY --list".equals(args)
                || "cmd_has_option HAVEKEY list".equals(args)) {
            // This extension is implemented below.
        } else if (args.startsWith("cmd_has_option ")) {
            throw new AgentException(FALSE, "False");
        } else {
            throw new AgentException(AgentException.NOT_SUPPORTED, "Unsupported information request");
        }
    }

    private void haveKey(String args, OutputStream out) throws AgentException, IOException {
        List<AgentKey> keys = backend.getKeys();
        if ("--list".equals(args) || args.startsWith("--list=")) {
            if (!"--list".equals(args)) {
                String limitText = args.substring(7);
                if (!limitText.matches("[0-9]{1,8}")) { throw invalid("Invalid key list limit"); }
                int limit = Integer.parseInt(limitText);
                if (limit < 1) { throw invalid("Key list limit must be positive"); }
                if (keys.size() > limit) { throw new AgentException(74, "Result truncated"); }
            }
            ByteArrayOutputStream grips = new ByteArrayOutputStream();
            for (AgentKey key : keys) {
                byte[] grip = fromHex(key.getKeygrip());
                grips.write(grip, 0, grip.length);
            }
            data(out, grips.toByteArray());
            return;
        }
        if (args.isEmpty()) { throw invalid("A keygrip is required"); }
        String[] requested = args.split(" +");
        boolean found = false;
        for (String grip : requested) {
            String canonical = parseKeygrip(grip);
            for (AgentKey key : keys) {
                found |= key.getKeygrip().equals(canonical);
            }
        }
        if (!found) { throw new AgentException(AgentException.NO_SECRET_KEY, "No shared secret key"); }
    }

    private void keyInfo(String args, OutputStream out) throws AgentException, IOException {
        if ("--list".equals(args)) {
            for (AgentKey key : backend.getKeys()) { keyInfoLine(out, key); }
        } else {
            keyInfoLine(out, findKey(parseKeygrip(args)));
        }
    }

    private void keyInfoLine(OutputStream out, AgentKey key) throws IOException {
        // D denotes a locally stored key on the phone. No passphrase is cached.
        writeLine(out, "S KEYINFO " + key.getKeygrip() + " D - - - P - - -");
    }

    private void setHash(String args) throws AgentException {
        clearDigest();
        String[] fields = args.split(" +");
        if (fields.length != 2) { throw invalid("Expected hash algorithm and hexadecimal digest"); }
        int algorithm;
        try {
            algorithm = Integer.parseInt(fields[0]);
        } catch (NumberFormatException e) {
            throw invalid("A numeric hash algorithm is required");
        }
        int size;
        switch (algorithm) {
            case 8: size = 32; break; // SHA256
            case 9: size = 48; break; // SHA384
            case 10: size = 64; break; // SHA512
            case 11: size = 28; break; // SHA224
            default: throw new AgentException(AgentException.NOT_SUPPORTED, "Unsupported hash algorithm");
        }
        if (fields[1].length() != size * 2 || !fields[1].matches("[a-fA-F0-9]+")) {
            throw invalid("Digest length or encoding does not match hash algorithm");
        }
        digest = fromHex(fields[1]);
        hashAlgorithm = algorithm;
    }

    private void sign(String args, OutputStream out) throws AgentException, IOException {
        // The optional token is a cache nonce, not a signing option. We do not
        // use it, and never let it change on-device authorization.
        if (!args.isEmpty() && !args.matches("(?:-- ?)?[a-zA-Z0-9_-]{0,128}")) {
            clearDigest();
            throw invalid("Unsupported PKSIGN argument");
        }
        if (keygrip == null || digest == null) {
            throw new AgentException(AgentException.NO_DATA, "SIGKEY and SETHASH are required");
        }
        AgentKey key = findKey(keygrip);
        byte[] requestedDigest = digest;
        int requestedHash = hashAlgorithm;
        String requestedDescription = description;
        digest = null;
        hashAlgorithm = 0;
        description = "";
        try {
            byte[] signature = backend.sign(key, requestedHash, requestedDigest, requestedDescription);
            if (signature == null || signature.length == 0 || signature.length > MAX_BACKEND_DATA) {
                throw new AgentException(AgentException.GENERAL, "Invalid signing response");
            }
            data(out, signature);
        } finally {
            Arrays.fill(requestedDigest, (byte) 0);
        }
    }

    private AgentKey findKey(String grip) throws AgentException {
        for (AgentKey key : backend.getKeys()) {
            if (key.getKeygrip().equals(grip)) { return key; }
        }
        throw new AgentException(AgentException.NO_SECRET_KEY, "No shared secret key");
    }

    private static String parseKeygrip(String value) throws AgentException {
        if (!value.matches("[a-fA-F0-9]{40}")) { throw invalid("Invalid keygrip"); }
        return value.toUpperCase(Locale.ROOT);
    }

    private static void requireEmpty(String args) throws AgentException {
        if (!args.isEmpty()) { throw invalid("Unexpected argument"); }
    }

    private static AgentException invalid(String message) {
        return new AgentException(AgentException.INVALID_VALUE, message);
    }

    private static String decodeDescription(String value) throws AgentException {
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        byte[] bytes = value.getBytes(UTF8);
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 255;
            if (b == '%') {
                if (i + 2 >= bytes.length) { throw invalid("Invalid description escape"); }
                int high = Character.digit((char) bytes[++i], 16);
                int low = Character.digit((char) bytes[++i], 16);
                if (high < 0 || low < 0) { throw invalid("Invalid description escape"); }
                b = high * 16 + low;
            } else if (b == '+') {
                b = ' ';
            }
            decoded.write(b);
        }
        return new String(decoded.toByteArray(), UTF8);
    }

    private static String readLine(InputStream in) throws IOException, LineException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                byte[] line = bytes.toByteArray();
                int length = line.length;
                if (length > 0 && line[length - 1] == '\r') { length--; }
                return new String(line, 0, length, UTF8);
            }
            if (b == 0 || (b < 32 && b != '\r') || b == 127) {
                throw new LineException("Invalid command character");
            }
            bytes.write(b);
            if (bytes.size() > MAX_LINE_BYTES - 1) {
                throw new LineException("Command exceeds Assuan line limit");
            }
        }
        if (bytes.size() != 0) { throw new LineException("Incomplete command"); }
        return null;
    }

    private static void error(OutputStream out, int code, String message) throws IOException {
        String safeMessage = message == null ? "Signing request failed" : message
                .replace('\r', ' ').replace('\n', ' ').replace('\0', ' ');
        if (safeMessage.length() > 200) { safeMessage = safeMessage.substring(0, 200); }
        writeLine(out, "ERR " + (ERROR_SOURCE_AGENT | code) + " " + safeMessage);
    }

    private static void data(OutputStream out, byte[] bytes) throws IOException {
        // The protocol's 1000-byte line maximum includes prefix and newline.
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        for (byte value : bytes) {
            int b = value & 255;
            int encodedSize = b == '%' || b == '\r' || b == '\n' ? 3 : 1;
            if (line.size() + encodedSize > MAX_LINE_BYTES - 3) {
                writeDataLine(out, line.toByteArray());
                line.reset();
            }
            if (encodedSize == 3) {
                line.write('%');
                line.write("0123456789ABCDEF".charAt(b >>> 4));
                line.write("0123456789ABCDEF".charAt(b & 15));
            } else {
                line.write(b);
            }
        }
        if (line.size() != 0) { writeDataLine(out, line.toByteArray()); }
    }

    private static void writeDataLine(OutputStream out, byte[] bytes) throws IOException {
        out.write('D');
        out.write(' ');
        out.write(bytes);
        out.write('\n');
    }

    private static void writeLine(OutputStream out, String line) throws IOException {
        out.write(line.getBytes(UTF8));
        out.write('\n');
        out.flush();
    }

    private static byte[] fromHex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (Character.digit(value.charAt(i * 2), 16) * 16
                    + Character.digit(value.charAt(i * 2 + 1), 16));
        }
        return bytes;
    }

    private void clearDigest() {
        if (digest != null) { Arrays.fill(digest, (byte) 0); }
        digest = null;
        hashAlgorithm = 0;
    }

    private void reset() {
        clearDigest();
        keygrip = null;
        description = "";
    }

    private static final class LineException extends Exception {
        LineException(String message) { super(message); }
    }
}
