package org.sufficientlysecure.keychain.remote.agent;

/** libgpg-error codes, without a source field. */
public final class AgentException extends Exception {
    public static final int GENERAL = 1;
    public static final int BAD_PASSPHRASE = 11;
    public static final int NO_SECRET_KEY = 17;
    public static final int INVALID_VALUE = 55;
    public static final int NO_DATA = 58;
    public static final int NOT_SUPPORTED = 60;
    public static final int CANCELED = 99;
    public static final int FORBIDDEN = 251;

    private final int code;

    public AgentException(int code, String message) {
        super(message);
        if (code <= 0 || code > 65535) {
            throw new IllegalArgumentException("Invalid libgpg-error code");
        }
        this.code = code;
    }

    public int getCode() { return code; }
}
