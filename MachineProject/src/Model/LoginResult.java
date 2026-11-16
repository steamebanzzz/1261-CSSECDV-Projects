package Model;

public final class LoginResult {

    private final boolean successful;
    private final String previousTime;
    private final String previousStatus;

    public LoginResult(
            boolean successful,
            String previousTime,
            String previousStatus) {

        this.successful = successful;
        this.previousTime = previousTime;
        this.previousStatus = previousStatus;
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
}