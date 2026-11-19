package Controller;

import View.Frame;
import View.UiGuard;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public class Main {

    public SQLite sqlite;

    public static void main(String[] args) {
        // Fail-safe: any exception that escapes a handler is caught here,
        // never printed as a stack trace, and the user is returned to the
        // unprivileged login screen (see UiGuard.handleUncaught).
        Thread.setDefaultUncaughtExceptionHandler(
                (thread, error) -> UiGuard.handleUncaught(error));
        SwingUtilities.invokeLater(() -> new Main().init());
    }

    public void init() {
        try {
            // Opens database.db, upgrades the schema, and replaces any
            // plaintext password with a salted hash. No credentials are
            // hard-coded in the source; demo accounts live in database.db.
            sqlite = new SQLite();
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(null,
                    "The application could not start. "
                    + "Please contact the system administrator.",
                    "SECURITY Svcs", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
            return;
        }

        Frame frame = new Frame();
        frame.init(this);
    }
}
