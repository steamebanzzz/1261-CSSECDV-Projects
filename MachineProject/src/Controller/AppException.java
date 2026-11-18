package Controller;

public final class AppException extends RuntimeException {
    
    private static final long serialVersionUID = 1L;

    private final boolean fatal;

    public AppException(String message, boolean fatal) {
        super(message);
        this.fatal = fatal;
    }

    public AppException(String message, boolean fatal, Throwable cause) {
        super(message, cause);
        this.fatal = fatal;
    }

    public boolean isFatal() {
        return fatal;
    }
}