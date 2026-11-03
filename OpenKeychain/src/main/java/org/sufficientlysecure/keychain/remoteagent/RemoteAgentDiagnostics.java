package org.sufficientlysecure.keychain.remoteagent;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogType;
import org.sufficientlysecure.keychain.operations.results.OperationResult.OperationLog;
import org.sufficientlysecure.keychain.ui.LogDisplayActivity;
import org.sufficientlysecure.keychain.ui.LogDisplayFragment;

/** In-memory technical diagnostics displayed with OpenKeychain's existing operation log UI. */
public final class RemoteAgentDiagnostics {
    private static final RemoteAgentDiagnosticBuffer BUFFER = new RemoteAgentDiagnosticBuffer();

    private RemoteAgentDiagnostics() {}

    public static void info(String message) {
        BUFFER.add(RemoteAgentDiagnosticBuffer.Level.INFO, message);
    }

    public static void warn(String message) {
        BUFFER.add(RemoteAgentDiagnosticBuffer.Level.WARN, message);
    }

    public static void error(String phase, Throwable throwable) {
        BUFFER.add(RemoteAgentDiagnosticBuffer.Level.ERROR,
                RemoteAgentDiagnosticBuffer.details(phase, throwable));
    }

    public static String failure(Throwable throwable) {
        return RemoteAgentDiagnosticBuffer.failure(throwable);
    }

    public static void clear() { BUFFER.clear(); }

    public static OperationResult result() {
        List<RemoteAgentDiagnosticBuffer.Entry> snapshot = BUFFER.snapshot();
        OperationLog log = new OperationLog();
        SimpleDateFormat timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS 'UTC'", Locale.ROOT);
        timestamp.setTimeZone(TimeZone.getTimeZone("UTC"));
        int resultCode = OperationResult.RESULT_OK;
        for (RemoteAgentDiagnosticBuffer.Entry entry : snapshot) {
            LogType type;
            switch (entry.level) {
                case ERROR:
                    type = LogType.MSG_REMOTE_AGENT_DIAGNOSTIC_ERROR;
                    resultCode |= OperationResult.RESULT_ERROR;
                    break;
                case WARN:
                    type = LogType.MSG_REMOTE_AGENT_DIAGNOSTIC_WARN;
                    resultCode |= OperationResult.RESULT_WARNINGS;
                    break;
                default: type = LogType.MSG_REMOTE_AGENT_DIAGNOSTIC_INFO;
            }
            log.add(type, 0, timestamp.format(new java.util.Date(entry.timeMillis)) + " " + entry.text);
        }
        return new Result(resultCode, log);
    }

    public static void open(Activity activity) {
        info("Diagnostics opened: Android " + Build.VERSION.RELEASE + "; API=" + Build.VERSION.SDK_INT
                + "; build=" + Build.DISPLAY + "; model=" + Build.MODEL);
        Intent intent = new Intent(activity, LogDisplayActivity.class);
        intent.putExtra(LogDisplayFragment.EXTRA_RESULT, result());
        activity.startActivity(intent);
    }

    /** Existing OperationResult parceling uses its process-local log cache; no disk persistence. */
    public static final class Result extends OperationResult {
        Result(int result, OperationLog log) { super(result, log); }
        private Result(Parcel source) { super(source); }

        public static final Parcelable.Creator<Result> CREATOR = new Parcelable.Creator<Result>() {
            @Override public Result createFromParcel(Parcel source) { return new Result(source); }
            @Override public Result[] newArray(int size) { return new Result[size]; }
        };
    }
}
