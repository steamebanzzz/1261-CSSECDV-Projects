package Controller;

/**
 * Raised when input fails validation or a business rule. Its message is
 * written by this application (never by a library and never containing the
 * rejected input), so it is the ONLY exception type whose message the UI may
 * show to the user. Every other exception is replaced by a generic message.
 */
public final class ValidationException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    public ValidationException(String message) {
        super(message);
    }
}
