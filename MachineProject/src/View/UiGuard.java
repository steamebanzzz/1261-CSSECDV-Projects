package View;

import Controller.AccessControl.Permission;
import Controller.AccessDeniedException;
import Controller.AppException;
import Controller.SQLite;
import Controller.ValidationException;
import java.awt.Component;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/**
 * Central error handling for the user interface.
 *
 *  - Only messages written by this application are ever shown
 *    (ValidationException, AccessDeniedException, AppException).
 *  - Anything else (NullPointerException, library exceptions, ...) is never
 *    displayed or printed: it is logged as UNEXPECTED_ERROR, the session is
 *    ended and the user is sent to the unprivileged login screen.
 */
public final class UiGuard {

    private static final String UNEXPECTED_MESSAGE =
            "An unexpected error occurred. For your security, "
            + "you have been signed out.";

    private static volatile Frame frame;
    private static boolean handlingFailure;

    private UiGuard() {
    }

    static void install(Frame applicationFrame) {
        frame = applicationFrame;
    }

    /** Runs a user action; any failure is handled safely. */
    public static boolean run(Component parent, Runnable action) {
        try {
            action.run();
            return true;
        } catch (RuntimeException ex) {
            handle(parent, ex);
            return false;
        }
    }

    /**
     * Opens a panel only if the current role may use both the home panel it
     * lives in and the feature itself; violations are logged by the
     * controller and the user is redirected.
     */
    static boolean open(Component parent, SQLite sqlite, Permission home,
            Permission feature, String resource, Runnable loader) {
        return run(parent, () -> {
            if (!sqlite.authorizeView(home, resource)
                    || !sqlite.authorizeView(feature, resource)) {
                throw new AccessDeniedException(
                        "You are not authorized to open " + resource + ".");
            }
            loader.run();
        });
    }

    public static void handle(Component parent, RuntimeException ex) {
        if (ex instanceof AppException && ((AppException) ex).isFatal()) {
            return; // the fatal-error handler already reset the UI
        }
        if (ex instanceof ValidationException) {
            JOptionPane.showMessageDialog(parent, ex.getMessage(),
                    "Invalid input", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (ex instanceof AccessDeniedException) {
            JOptionPane.showMessageDialog(parent, ex.getMessage(),
                    "Access denied", JOptionPane.ERROR_MESSAGE);
            Frame current = frame;
            if (current != null) {
                current.enforceSession();
            }
            return;
        }
        if (ex instanceof AppException) {
            JOptionPane.showMessageDialog(parent, ex.getMessage(),
                    "Request failed", JOptionPane.ERROR_MESSAGE);
            return;
        }
        failSafe(ex);
    }

    /** Default uncaught-exception handler (installed by Main). */
    public static void handleUncaught(Throwable error) {
        if (SwingUtilities.isEventDispatchThread()) {
            failSafe(error);
        } else {
            SwingUtilities.invokeLater(() -> failSafe(error));
        }
    }

    private static void failSafe(Throwable error) {
        if (handlingFailure) {
            return; // never loop if the recovery itself fails
        }
        handlingFailure = true;
        try {
            Frame current = frame;
            if (current != null) {
                current.resetToLogin(error == null ? null
                        : error.getClass().getSimpleName());
            }
            JOptionPane.showMessageDialog(current, UNEXPECTED_MESSAGE,
                    "Session ended", JOptionPane.ERROR_MESSAGE);
        } catch (Throwable ignored) {
            // Nothing is printed: stack traces are never shown to users.
        } finally {
            handlingFailure = false;
        }
    }
}
