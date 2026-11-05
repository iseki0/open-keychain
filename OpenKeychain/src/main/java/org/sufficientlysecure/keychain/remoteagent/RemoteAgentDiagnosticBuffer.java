package org.sufficientlysecure.keychain.remoteagent;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pure Java, bounded diagnostics storage. Callers must never deliberately supply secrets. */
final class RemoteAgentDiagnosticBuffer {
    static final int MAX_ENTRIES = 128;
    static final int MAX_ENTRY_CHARS = 2048;
    static final int MAX_TOTAL_CHARS = 180000;
    private static final int MAX_INPUT_CHARS = 65536;
    private static final String TRUNCATED = " [truncated]";
    private static final String REDACTED = "[redacted]";
    private static final Pattern PRIVATE_KEY = Pattern.compile(
            "(?is)-----BEGIN [^-\\r\\n]*(?:PRIVATE|SECRET) KEY(?: BLOCK)?-----.*?"
                    + "(?:-----END [^-\\r\\n]*(?:PRIVATE|SECRET) KEY(?: BLOCK)?-----|\\z)");
    private static final Pattern BRIDGE_TICKET = Pattern.compile("(?i)gpgbridge:v1:[A-Za-z0-9_+/=-]*");
    private static final Pattern TAILSCALE_KEY = Pattern.compile("(?i)\\b(?:tskey-[A-Za-z0-9_-]+|privkey:[A-Za-z0-9]+)");
    private static final Pattern TAILSCALE_LOGIN = Pattern.compile(
            "(?i)(?:https?://)?login\\.tailscale\\.com/[^\\s<>\\\"']*");
    private static final Pattern URL = Pattern.compile("(?i)https?://[^\\s<>\\\"']+");
    private static final Pattern AUTH_PATH = Pattern.compile("(?i)^/(?:a|register|auth|login)(?:/|$)");
    private static final Pattern AUTHORIZATION = Pattern.compile(
            "(?i)\\b(?:proxy[-_ ]?authorization|headerauthorization|authorization)[\\\"']?\\s*[:=]\\s*");
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?i)\\b(?:Bearer|Basic)\\s+[A-Za-z0-9._~+/=-]+");
    private static final Pattern CREDENTIAL = Pattern.compile(
            "(?i)\\b(?:password|passphrase|passwd|pwd|psk|pre[-_]?shared[-_]?key|secret|"
                    + "client[-_]?secret|(?:ts[-_]?)?auth[-_]?key|auth[-_]?url|access[-_]?token|"
                    + "refresh[-_]?token|token|ticket|private[-_]?key|api[-_]?key|key|credentials?)"
                    + "[\\\"']?\\s*[:=]\\s*");

    enum Level { INFO, WARN, ERROR }

    static final class Entry {
        final Level level;
        final String text;
        final long timeMillis;

        Entry(Level level, String text) {
            this.level = level;
            this.text = text;
            this.timeMillis = System.currentTimeMillis();
        }
    }

    private final ArrayDeque<Entry> entries = new ArrayDeque<>();
    private int totalChars;

    synchronized void add(Level level, String text) {
        Entry entry = new Entry(level, sanitize(text));
        entries.addLast(entry);
        totalChars += entry.text.length();
        while (entries.size() > MAX_ENTRIES || totalChars > MAX_TOTAL_CHARS) {
            totalChars -= entries.removeFirst().text.length();
        }
    }

    synchronized List<Entry> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    synchronized void clear() {
        entries.clear();
        totalChars = 0;
    }

    /** Redact before shortening, including incomplete credentials at a truncation boundary. */
    static String sanitize(String source) {
        if (source == null) return "";
        boolean oversized = source.length() > MAX_INPUT_CHARS;
        String value = oversized ? source.substring(0, MAX_INPUT_CHARS) : source;
        value = PRIVATE_KEY.matcher(value).replaceAll("[redacted-private-key]");
        value = BRIDGE_TICKET.matcher(value).replaceAll("[redacted-ticket]");
        value = TAILSCALE_KEY.matcher(value).replaceAll("[redacted-tailscale-key]");
        value = TAILSCALE_LOGIN.matcher(value).replaceAll("login.tailscale.com/[redacted-auth-url]");
        Matcher urls = URL.matcher(value);
        StringBuffer safeURLs = new StringBuffer();
        while (urls.find()) urls.appendReplacement(safeURLs, Matcher.quoteReplacement(sanitizeURL(urls.group())));
        urls.appendTail(safeURLs);
        value = redactValues(safeURLs.toString(), AUTHORIZATION, true);
        value = redactValues(value, CREDENTIAL, false);
        value = AUTH_SCHEME.matcher(value).replaceAll("[redacted-authorization]");
        StringBuilder safe = new StringBuilder();
        for (int i = 0; i < value.length() && safe.length() <= MAX_ENTRY_CHARS; i++) {
            char c = value.charAt(i);
            if (c == '\r') {
                if (i + 1 < value.length() && value.charAt(i + 1) == '\n') i++;
                safe.append('\n');
            } else if ((Character.isISOControl(c) && c != '\n' && c != '\t')
                    || Character.getType(c) == Character.FORMAT) {
                safe.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else safe.append(c);
        }
        if (oversized || value.length() > MAX_ENTRY_CHARS || safe.length() > MAX_ENTRY_CHARS) {
            return limit(safe.toString(), MAX_ENTRY_CHARS - TRUNCATED.length()) + TRUNCATED;
        }
        return safe.toString();
    }

    private static String sanitizeURL(String value) {
        try {
            URI uri = new URI(value);
            String host = uri.getHost();
            String path = uri.getPath();
            if ((host != null && host.equalsIgnoreCase("login.tailscale.com"))
                    || (path != null && AUTH_PATH.matcher(path).find())) {
                return uri.getScheme() + "://" + (host == null ? "[redacted-host]" : host)
                        + (uri.getPort() < 0 ? "" : ":" + uri.getPort()) + "/[redacted-auth-url]";
            }
            if (uri.getRawUserInfo() != null) {
                return value.replace(uri.getRawUserInfo() + "@", REDACTED + "@");
            }
        } catch (Exception ignored) {
            // Even a malformed URL must not disclose user:password credentials.
        }
        return value.replaceFirst("(?i)^(https?://)[^/@\\s]+@", "$1[redacted]@");
    }

    private static String redactValues(String value, Pattern labels, boolean header) {
        Matcher matches = labels.matcher(value);
        StringBuilder output = new StringBuilder();
        int copied = 0;
        while (matches.find()) {
            int start = matches.end();
            int end = start;
            if (value.startsWith("[redacted", start) && value.indexOf(']', start) >= start) {
                end = value.indexOf(']', start) + 1;
            } else if (start < value.length() && (value.charAt(start) == '"' || value.charAt(start) == '\'')) {
                char quote = value.charAt(start);
                end++;
                // Scan rather than a recursive regex: escaped and unterminated quoted values
                // (including a truncation at the input limit) must be redacted in their entirety.
                while (end < value.length()) {
                    char c = value.charAt(end++);
                    if (c == '\\' && end < value.length()) end++;
                    else if (c == quote) break;
                }
            } else {
                while (end < value.length()) {
                    char c = value.charAt(end);
                    if ((header && (c == '\n' || c == '\r'))
                            || (!header && (Character.isWhitespace(c) || "&,;]}".indexOf(c) >= 0))) break;
                    end++;
                }
            }
            output.append(value, copied, start).append(REDACTED);
            copied = end;
            matches.region(end, value.length());
        }
        return output.append(value, copied, value.length()).toString();
    }

    /** Root cause comes first so a wrapper or long native error cannot hide its useful cause. */
    static String failure(Throwable throwable) {
        if (throwable == null) return "Unknown failure";
        List<Throwable> chain = causes(throwable);
        StringBuilder summary = new StringBuilder();
        for (int i = chain.size() - 1; i >= 0; i--) {
            Throwable cause = chain.get(i);
            if (summary.length() > 0) summary.append("\nWrapped by: ");
            summary.append(cause.getClass().getName());
            String message = sanitize(cause.getMessage());
            if (!message.isEmpty()) summary.append(": ").append(limit(message, 512));
            if (summary.length() >= MAX_ENTRY_CHARS) break;
        }
        return sanitize(summary.toString());
    }

    static String details(String phase, Throwable throwable) {
        StringBuilder details = new StringBuilder(limit(sanitize(phase), 256));
        details.append('\n').append(limit(failure(throwable), 768));
        List<Throwable> chain = causes(throwable);
        for (int i = chain.size() - 1; i >= 0 && details.length() < MAX_ENTRY_CHARS; i--) {
            Throwable cause = chain.get(i);
            details.append("\nStack: ").append(cause.getClass().getName());
            StackTraceElement[] trace = cause.getStackTrace();
            for (int frame = 0; frame < trace.length && frame < 16 && details.length() < MAX_ENTRY_CHARS; frame++) {
                details.append("\n  at ").append(limit(sanitize(trace[frame].toString()), 240));
            }
        }
        return sanitize(details.toString());
    }

    private static List<Throwable> causes(Throwable throwable) {
        List<Throwable> result = new ArrayList<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        while (throwable != null && result.size() < 16 && seen.add(throwable)) {
            result.add(throwable);
            throwable = throwable.getCause();
        }
        return result;
    }

    private static String limit(String value, int length) {
        if (value.length() <= length) return value;
        int end = length;
        if (end > 0 && Character.isHighSurrogate(value.charAt(end - 1))) end--;
        return value.substring(0, end);
    }
}
