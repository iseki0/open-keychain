package org.sufficientlysecure.keychain.remoteagent;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Small immutable UI snapshot. Parse native status on the service worker, never on the UI thread. */
public final class RemoteAgentStatus {
    public static final int MAX_JSON_CHARS = 16 * 1024;
    private static final int MAX_JSON_DEPTH = 32;
    private static final int MAX_LOGIN_URL_CHARS = 4096;

    public final String backendState;
    public final String addresses;
    public final String health;
    public final String loginUrl;
    public final String message;
    public final boolean failed;

    private RemoteAgentStatus(String backendState, String addresses, String health,
            String loginUrl, String message, boolean failed) {
        this.backendState = backendState;
        this.addresses = addresses;
        this.health = health;
        this.loginUrl = loginUrl;
        this.message = message;
        this.failed = failed;
    }

    public static RemoteAgentStatus initial() {
        return message("Disconnected");
    }

    public static RemoteAgentStatus message(String message) {
        return new RemoteAgentStatus("", "", "", null, display(message, 1024), false);
    }

    public static RemoteAgentStatus failure(String message) {
        return new RemoteAgentStatus("", "", "", null, display(message, 1024), true);
    }

    /** Reject oversized legacy payloads before allocating a JSON object graph. */
    public static RemoteAgentStatus parse(String json) {
        if (json == null || json.length() > MAX_JSON_CHARS) {
            throw new IllegalArgumentException("Tailscale status exceeds the safe size limit");
        }
        checkDepth(json);
        try {
            JSONTokener tokens = new JSONTokener(json);
            Object value = tokens.nextValue();
            if (!(value instanceof JSONObject) || tokens.nextClean() != 0) {
                throw new IllegalArgumentException("Invalid Tailscale status object");
            }
            JSONObject status = (JSONObject) value;
            return new RemoteAgentStatus(display(string(status, "BackendState"), 128),
                    strings(status, "TailscaleIPs", 8, 64, ", "),
                    strings(status, "Health", 4, 128, "\n"),
                    loginUrl(string(status, "AuthURL")), null, false);
        } catch (JSONException failure) {
            // JSONTokener exception messages can contain the entire input, including AuthURL.
            throw new IllegalArgumentException("Invalid Tailscale status JSON");
        }
    }

    private static String string(JSONObject status, String key) {
        Object value = status.opt(key);
        if (value == null || value == JSONObject.NULL) return "";
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("Invalid Tailscale status field: " + key);
        }
        return (String) value;
    }

    private static String strings(JSONObject status, String key, int maxEntries,
            int maxEntryChars, String separator) throws JSONException {
        Object value = status.opt(key);
        if (value == null || value == JSONObject.NULL) return "";
        if (!(value instanceof JSONArray)) {
            throw new IllegalArgumentException("Invalid Tailscale status field: " + key);
        }
        JSONArray values = (JSONArray) value;
        StringBuilder text = new StringBuilder();
        for (int index = 0; index < values.length(); index++) {
            Object item = values.get(index);
            if (!(item instanceof String)) {
                throw new IllegalArgumentException("Invalid Tailscale status entry: " + key);
            }
            if (index >= maxEntries) continue;
            String entry = display((String) item, maxEntryChars);
            if (entry.isEmpty()) continue;
            if (text.length() > 0) text.append(separator);
            text.append(entry);
        }
        if (values.length() > maxEntries) text.append('\u2026');
        return display(text.toString(), 512, separator.equals("\n"));
    }

    private static String loginUrl(String url) {
        if (url.isEmpty() || url.length() > MAX_LOGIN_URL_CHARS) return null;
        for (int index = 0; index < url.length(); index++) {
            char value = url.charAt(index);
            if (Character.isISOControl(value) || Character.isWhitespace(value)
                    || Character.getType(value) == Character.FORMAT) return null;
        }
        try {
            URI uri = new URI(url);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getHost().isEmpty() || uri.getRawUserInfo() != null
                    || uri.getPort() > 65535) return null;
            return url;
        } catch (URISyntaxException failure) {
            return null;
        }
    }

    private static String display(String value, int maxChars) {
        return display(value, maxChars, false);
    }

    private static String display(String value, int maxChars, boolean keepNewlines) {
        if (value == null || value.isEmpty()) return "";
        boolean truncated = value.length() > maxChars;
        int length = truncated ? maxChars - 1 : value.length();
        // Never cut a supplementary character between its UTF-16 surrogate halves.
        if (length > 0 && length < value.length() && Character.isHighSurrogate(value.charAt(length - 1))
                && Character.isLowSurrogate(value.charAt(length))) length--;
        StringBuilder text = new StringBuilder(maxChars);
        for (int index = 0; index < length; index++) {
            char character = value.charAt(index);
            int type = Character.getType(character);
            if ((Character.isISOControl(character) && !(keepNewlines && character == '\n'))
                    || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) character = ' ';
            text.append(character);
        }
        if (truncated) text.append('\u2026');
        return text.toString().trim();
    }

    /** JSONObject recursively parses arrays/objects; a small pathological payload can exhaust the stack. */
    private static void checkDepth(String json) {
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int index = 0; index < json.length(); index++) {
            char character = json.charAt(index);
            if (quoted) {
                if (escaped) escaped = false;
                else if (character == '\\') escaped = true;
                else if (character == '"') quoted = false;
            } else if (character == '"') {
                quoted = true;
            } else if (character == '\'' || character == '/' || character == '#') {
                // JSONTokener accepts nonstandard quotes/comments; disallow them so they cannot
                // hide nesting from the nonrecursive guard above.
                throw new IllegalArgumentException("Invalid Tailscale status JSON syntax");
            } else if (character == '{' || character == '[') {
                if (++depth > MAX_JSON_DEPTH) {
                    throw new IllegalArgumentException("Tailscale status is nested too deeply");
                }
            } else if (character == '}' || character == ']') {
                if (--depth < 0) throw new IllegalArgumentException("Invalid Tailscale status nesting");
            }
        }
        if (quoted || depth != 0) throw new IllegalArgumentException("Invalid Tailscale status nesting");
    }

    @Override public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof RemoteAgentStatus)) return false;
        RemoteAgentStatus status = (RemoteAgentStatus) other;
        return failed == status.failed && backendState.equals(status.backendState)
                && addresses.equals(status.addresses) && health.equals(status.health)
                && Objects.equals(loginUrl, status.loginUrl) && Objects.equals(message, status.message);
    }

    @Override public int hashCode() {
        return Objects.hash(backendState, addresses, health, loginUrl, message, failed);
    }
}
