package Model;

public final class Logs {

    private final int id;
    private final String event;
    private final String username;
    private final String desc;
    private final String timestamp;

    public Logs(
            int id,
            String event,
            String username,
            String desc,
            String timestamp) {

        this.id = id;
        this.event = event;
        this.username = username;
        this.desc = desc;
        this.timestamp = timestamp;
    }

    public int getId() {
        return id;
    }

    public String getEvent() {
        return event;
    }

    public String getUsername() {
        return username;
    }

    public String getDesc() {
        return desc;
    }

    public String getTimestamp() {
        return timestamp;
    }
}