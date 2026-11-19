package Model;

public final class User {

    private final int id;
    private final String username;
    private final int role;
    private final int locked;
    private final int failedAttempts;

    public User(
            int id,
            String username,
            int role,
            int locked,
            int failedAttempts) {

        this.id = id;
        this.username = username;
        this.role = role;
        this.locked = locked;
        this.failedAttempts = failedAttempts;
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public int getRole() {
        return role;
    }

    public int getLocked() {
        return locked;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }
}