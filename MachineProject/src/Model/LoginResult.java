package Model;

/**
 * Outcome of a login attempt. A failure carries no detail at all, so the UI
 * cannot accidentally reveal why the attempt failed (account enumeration).
 */
public final class LoginResult {

    private static final LoginResult FAILURE =
            new LoginResult(false, null, null, null, 0);

    private final boolean successful;
    private final String previousTime;
    private final String previousStatus;
    private final String lastSuccessfulLogin;
    private final int failedAttemptsSinceLastLogin;

    private LoginResult(boolean successful, String previousTime,
            String previousStatus, String lastSuccessfulLogin,
            int failedAttemptsSinceLastLogin) {
        this.successful = successful;
        this.previousTime = previousTime;
        this.previousStatus = previousStatus;
        this.lastSuccessfulLogin = lastSuccessfulLogin;
        this.failedAttemptsSinceLastLogin = failedAttemptsSinceLastLogin;
    }

    public static LoginResult failure() {
        return FAILURE;
    }

    public static LoginResult success(String previousTime,
            String previousStatus, String lastSuccessfulLogin,
            int failedAttemptsSinceLastLogin) {
        return new LoginResult(true, previousTime, previousStatus,
                lastSuccessfulLogin, failedAttemptsSinceLastLogin);
    }

    public boolean isSuccessful() {
        return successful;
    }

    public String getPreviousTime() {
        return previousTime;
    }

    public String getPreviousStatus() {
        return previousStatus;
    }

    public String getLastSuccessfulLogin() {
        return lastSuccessfulLogin;
    }

    public int getFailedAttemptsSinceLastLogin() {
        return failedAttemptsSinceLastLogin;
    }
}
