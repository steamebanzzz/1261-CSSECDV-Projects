
package Model;

public final class LoginResult {

    private final boolean successful;
    private final boolean locked;
    private final String previousTime;
    private final String previousStatus;
    private final String lastSuccessfulLogin;

    public LoginResult(
            boolean successful,
            String previousTime,
            String previousStatus) {
        this(successful, false, previousTime, previousStatus, null);
    }

    public LoginResult(
            boolean successful,
            String previousTime,
            String previousStatus,
            String lastSuccessfulLogin) {
        this(successful, false, previousTime, previousStatus,
                lastSuccessfulLogin);
    }

    public LoginResult(
            boolean successful,
            boolean locked,
            String previousTime,
            String previousStatus,
            String lastSuccessfulLogin) {

        this.successful = successful;
        this.locked = locked;
        this.previousTime = previousTime;
        this.previousStatus = previousStatus;
        this.lastSuccessfulLogin = lastSuccessfulLogin;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public boolean isLocked() {
        return locked;
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
}
