package Controller;

/**
 * Raised by the central authorization check when the current session (or the
 * lack of one) is not allowed to perform an operation. The message is a fixed,
 * application-written string that is safe to show to the user.
 */
public final class AccessDeniedException extends SecurityException {

    private static final long serialVersionUID = 1L;

    public AccessDeniedException(String message) {
        super(message);
    }
}
