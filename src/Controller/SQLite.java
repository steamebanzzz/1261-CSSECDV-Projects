package Controller;

import Controller.AccessControl.Permission;
import Model.History;
import Model.LoginResult;
import Model.Logs;
import Model.Product;
import Model.User;
import java.io.File;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Data-access controller. SECURITY DESIGN:
 *  - Every public operation first calls authorize(...), which re-reads the
 *    session's account from the database and checks it against the single
 *    AccessControl policy (default deny, every denial logged).
 *  - Every SQL statement is a PreparedStatement; user data is only ever bound
 *    as a parameter, never concatenated into SQL. Every SQL string is a
 *    compile-time constant: no SQL text is assembled at run time, not even
 *    the schema-upgrade DDL (which JDBC cannot parameterize).
 *  - Inputs are validated with Validation (reject, never sanitize) and every
 *    rejection is written to the security log.
 *  - SQLException and other technical errors are never shown to the user;
 *    they are converted into AppException with a generic message.
 */
public class SQLite {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    /** Stand-in verified when a login password has an invalid length. */
    private static final char[] LENGTH_PLACEHOLDER = {'-'};
    private static final String ANONYMOUS = "<anonymous>";
    private static final String DENIED_MESSAGE =
            "You are not authorized to perform this action.";
    private static final String ADMIN_TARGET_MESSAGE =
            "Administrator accounts can only be managed by the "
            + "super administrator.";

    private final File databaseFile;
    private final String driverURL;
    private final String dummyHash;
    private volatile AuthenticatedUser session;
    private volatile Runnable fatalErrorHandler;

    private static final class AuthenticatedUser {
        private final int id;
        private final String username;
        private final int role;

        private AuthenticatedUser(int id, String username, int role) {
            this.id = id;
            this.username = username;
            this.role = role;
        }
    }

    private static final class Account {
        private final int id;
        private final String username;
        private final int role;
        private final int locked;
        private final Integer roleBeforeLock;

        private Account(int id, String username, int role, int locked,
                Integer roleBeforeLock) {
            this.id = id;
            this.username = username;
            this.role = role;
            this.locked = locked;
            this.roleBeforeLock = roleBeforeLock;
        }

        /** Admin accounts, including locked ones, are off-limits. */
        private boolean isAdministrator() {
            return role == AccessControl.ADMIN
                    || (roleBeforeLock != null
                    && roleBeforeLock == AccessControl.ADMIN);
        }
    }

    public SQLite() {
        databaseFile = resolveDatabaseFile();
        driverURL = "jdbc:sqlite:" + databaseFile.getPath();
        dummyHash = createDummyHash();
        initializeDatabase();
    }

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    /**
     * Picks ONE database file, independent of how the program is launched:
     *  1. the path in the system property cssecdv.db, if set;
     *  2. when running from a JAR: database.db beside the JAR, always
     *     (the working directory is ignored, so "java -jar dist/CSSECDV.jar"
     *     and double-clicking the JAR use the same file);
     *  3. otherwise (NetBeans run, tests): database.db in the working
     *     directory, i.e. the project folder.
     */
    private static File resolveDatabaseFile() {
        String override = System.getProperty("cssecdv.db");
        if (override != null && !override.trim().isEmpty()) {
            return new File(override.trim()).getAbsoluteFile();
        }
        try {
            File code = new File(SQLite.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            if (code.isFile()) {
                return new File(code.getParentFile(), "database.db")
                        .getAbsoluteFile();
            }
        } catch (Exception ex) {
            // Location unknown: fall back to the working directory.
        }
        return new File("database.db").getAbsoluteFile();
    }

    /** Absolute path of the database file this instance uses. */
    public String getDatabasePath() {
        return databaseFile.getPath();
    }

    /** Hash of a random secret, used to equalize login timing. */
    private static String createDummyHash() {
        SecureRandom random = new SecureRandom();
        char[] secret = new char[24];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (char) ('!' + random.nextInt(94));
        }
        try {
            return PasswordHasher.hash(secret);
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(driverURL);
    }

    private void initializeDatabase() {
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                execute(conn, "CREATE TABLE IF NOT EXISTS users ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "username TEXT NOT NULL UNIQUE,"
                        + "password TEXT NOT NULL,"
                        + "role INTEGER DEFAULT 2,"
                        + "locked INTEGER DEFAULT 0)");
                execute(conn, "CREATE TABLE IF NOT EXISTS product ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "name TEXT NOT NULL UNIQUE,"
                        + "stock INTEGER DEFAULT 0,"
                        + "price REAL DEFAULT 0.00)");
                execute(conn, "CREATE TABLE IF NOT EXISTS history ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "username TEXT NOT NULL,"
                        + "name TEXT NOT NULL,"
                        + "stock INTEGER DEFAULT 0,"
                        + "timestamp TEXT NOT NULL)");
                execute(conn, "CREATE TABLE IF NOT EXISTS logs ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "event TEXT NOT NULL,"
                        + "username TEXT NOT NULL,"
                        + "desc TEXT NOT NULL,"
                        + "timestamp TEXT NOT NULL)");

                for (ColumnUpgrade upgrade : COLUMN_UPGRADES) {
                    if (!columnExists(conn, upgrade.table, upgrade.column)) {
                        execute(conn, upgrade.alterTableSql);
                    }
                }

                execute(conn, "UPDATE users SET role_before_lock = role "
                        + "WHERE locked = 1 AND role BETWEEN 2 AND 5 "
                        + "AND role_before_lock IS NULL");
                execute(conn, "UPDATE history SET user_id = ("
                        + "SELECT id FROM users WHERE "
                        + "users.username = history.username) "
                        + "WHERE user_id IS NULL");
                execute(conn, "UPDATE history SET product_id = ("
                        + "SELECT id FROM product WHERE "
                        + "product.name = history.name) "
                        + "WHERE product_id IS NULL");
                execute(conn, "UPDATE history SET unit_price_cents = ("
                        + "SELECT CAST(ROUND(price * 100) AS INTEGER) "
                        + "FROM product WHERE product.name = history.name) "
                        + "WHERE unit_price_cents IS NULL "
                        + "AND EXISTS (SELECT 1 FROM product "
                        + "WHERE product.name = history.name)");
                execute(conn, "CREATE INDEX IF NOT EXISTS "
                        + "history_user_id_idx ON history(user_id)");
                execute(conn, "CREATE INDEX IF NOT EXISTS "
                        + "history_product_id_idx ON history(product_id)");
                execute(conn, "CREATE INDEX IF NOT EXISTS "
                        + "logs_timestamp_idx ON logs(timestamp)");
                // Usernames are case-insensitive: "Admin" == "admin".
                execute(conn, "CREATE UNIQUE INDEX IF NOT EXISTS "
                        + "users_username_nocase_idx "
                        + "ON users(username COLLATE NOCASE)");

                createUserConstraints(conn);
                migratePlaintextPasswords(conn);
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw fatalException(
                    "Database initialization could not be completed.", ex);
        }
    }

    /**
     * Database-level constraints on the users table (defense in depth for
     * checklist 2.3.2 / 2.3.3): even a direct edit of database.db, e.g. in
     * DB Browser, cannot store a role outside 1-5, a locked flag other than
     * 0/1, a negative failed-attempt count, or a username that breaks the
     * [A-Za-z0-9]{3,32} rule. The write is rejected outright (never
     * corrected), matching the reject-by-default policy.
     *
     * Triggers are used because SQLite cannot add CHECK constraints to an
     * existing table without rebuilding it. They are "gentle": they only
     * look at the columns a statement actually writes, so a pre-existing
     * bad row does not break unrelated updates (the login code still
     * blocks such an account).
     */
    private static void createUserConstraints(Connection conn)
            throws SQLException {
        execute(conn, "CREATE TRIGGER IF NOT EXISTS users_validate_insert "
                + "BEFORE INSERT ON users BEGIN SELECT CASE "
                + "WHEN typeof(NEW.role) <> 'integer' "
                + "OR NEW.role NOT BETWEEN 1 AND 5 "
                + "THEN RAISE(ABORT, 'role must be an integer from 1 to 5') "
                + "WHEN NEW.locked IS NOT NULL AND NEW.locked NOT IN (0, 1) "
                + "THEN RAISE(ABORT, 'locked must be 0 or 1') "
                + "WHEN typeof(NEW.failed_attempts) <> 'integer' "
                + "OR NEW.failed_attempts < 0 "
                + "THEN RAISE(ABORT, "
                + "'failed_attempts must be a non-negative integer') "
                + "WHEN NEW.role_before_lock IS NOT NULL "
                + "AND NEW.role_before_lock NOT IN (2, 3, 4, 5) "
                + "THEN RAISE(ABORT, "
                + "'role_before_lock must be empty or 2 to 5') "
                + "WHEN typeof(NEW.username) <> 'text' "
                + "OR length(NEW.username) NOT BETWEEN 3 AND 32 "
                + "OR NEW.username GLOB '*[^A-Za-z0-9]*' "
                + "THEN RAISE(ABORT, "
                + "'username must be 3-32 letters or digits') "
                + "END; END");
        execute(conn, "CREATE TRIGGER IF NOT EXISTS users_validate_update "
                + "BEFORE UPDATE OF role, locked, failed_attempts, "
                + "role_before_lock, username ON users BEGIN SELECT CASE "
                + "WHEN NEW.role IS NOT OLD.role "
                + "AND (typeof(NEW.role) <> 'integer' "
                + "OR NEW.role NOT BETWEEN 1 AND 5) "
                + "THEN RAISE(ABORT, 'role must be an integer from 1 to 5') "
                + "WHEN NEW.locked IS NOT OLD.locked "
                + "AND (NEW.locked IS NULL OR NEW.locked NOT IN (0, 1)) "
                + "THEN RAISE(ABORT, 'locked must be 0 or 1') "
                + "WHEN NEW.failed_attempts IS NOT OLD.failed_attempts "
                + "AND (typeof(NEW.failed_attempts) <> 'integer' "
                + "OR NEW.failed_attempts < 0) "
                + "THEN RAISE(ABORT, "
                + "'failed_attempts must be a non-negative integer') "
                + "WHEN NEW.role_before_lock IS NOT OLD.role_before_lock "
                + "AND NEW.role_before_lock IS NOT NULL "
                + "AND NEW.role_before_lock NOT IN (2, 3, 4, 5) "
                + "THEN RAISE(ABORT, "
                + "'role_before_lock must be empty or 2 to 5') "
                + "WHEN NEW.username IS NOT OLD.username "
                + "AND (typeof(NEW.username) <> 'text' "
                + "OR length(NEW.username) NOT BETWEEN 3 AND 32 "
                + "OR NEW.username GLOB '*[^A-Za-z0-9]*') "
                + "THEN RAISE(ABORT, "
                + "'username must be 3-32 letters or digits') "
                + "END; END");
    }

    private static void execute(Connection conn, String sql)
            throws SQLException {
        try (PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.execute();
        }
    }

    /**
     * One column added to a database created by the original starter.
     * Table and column names cannot be bound as "?" parameters in DDL, so
     * each upgrade carries its complete ALTER TABLE statement as a
     * compile-time constant; nothing is concatenated at run time.
     */
    private static final class ColumnUpgrade {
        private final String table;
        private final String column;
        private final String alterTableSql;

        private ColumnUpgrade(String table, String column,
                String alterTableSql) {
            this.table = table;
            this.column = column;
            this.alterTableSql = alterTableSql;
        }
    }

    private static final ColumnUpgrade[] COLUMN_UPGRADES = {
        new ColumnUpgrade("users", "failed_attempts",
                "ALTER TABLE users ADD COLUMN failed_attempts "
                + "INTEGER NOT NULL DEFAULT 0"),
        new ColumnUpgrade("users", "role_before_lock",
                "ALTER TABLE users ADD COLUMN role_before_lock INTEGER"),
        new ColumnUpgrade("users", "last_login_attempt_at",
                "ALTER TABLE users ADD COLUMN last_login_attempt_at TEXT"),
        new ColumnUpgrade("users", "last_login_status",
                "ALTER TABLE users ADD COLUMN last_login_status TEXT"),
        new ColumnUpgrade("users", "last_successful_login_at",
                "ALTER TABLE users ADD COLUMN last_successful_login_at "
                + "TEXT"),
        new ColumnUpgrade("history", "user_id",
                "ALTER TABLE history ADD COLUMN user_id INTEGER"),
        new ColumnUpgrade("history", "product_id",
                "ALTER TABLE history ADD COLUMN product_id INTEGER"),
        new ColumnUpgrade("history", "unit_price_cents",
                "ALTER TABLE history ADD COLUMN unit_price_cents INTEGER"),
        new ColumnUpgrade("logs", "archived",
                "ALTER TABLE logs ADD COLUMN archived "
                + "INTEGER NOT NULL DEFAULT 0"),
        new ColumnUpgrade("logs", "archived_at",
                "ALTER TABLE logs ADD COLUMN archived_at TEXT"),
        new ColumnUpgrade("logs", "archived_by",
                "ALTER TABLE logs ADD COLUMN archived_by TEXT")
    };

    /** Table and column are bound as parameters of pragma_table_info. */
    private static boolean columnExists(
            Connection conn, String table, String column)
            throws SQLException {
        try (PreparedStatement statement = conn.prepareStatement(
                "SELECT 1 FROM pragma_table_info(?) WHERE name = ?")) {
            statement.setString(1, table);
            statement.setString(2, column);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** Replaces any plaintext password left in the database by a hash. */
    private static void migratePlaintextPasswords(Connection conn)
            throws SQLException {
        List<Integer> ids = new ArrayList<Integer>();
        List<String> usernames = new ArrayList<String>();
        List<String> passwords = new ArrayList<String>();
        try (PreparedStatement statement = conn.prepareStatement(
                "SELECT id, username, password FROM users");
                ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                String stored = rs.getString("password");
                if (!PasswordHasher.isHash(stored)) {
                    ids.add(rs.getInt("id"));
                    usernames.add(rs.getString("username"));
                    passwords.add(stored == null ? "" : stored);
                }
            }
        }
        for (int i = 0; i < ids.size(); i++) {
            char[] plain = passwords.get(i).toCharArray();
            try (PreparedStatement update = conn.prepareStatement(
                    "UPDATE users SET password = ? WHERE id = ?")) {
                update.setString(1, PasswordHasher.hash(plain));
                update.setInt(2, ids.get(i));
                update.executeUpdate();
            } finally {
                Arrays.fill(plain, '\0');
            }
            insertLog(conn, "PASSWORD_HASH_MIGRATED", usernames.get(i),
                    "Plaintext password replaced with a salted "
                    + "PBKDF2-HMAC-SHA256 hash", timestamp());
        }
    }

    // ------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------

    public synchronized LoginResult login(String username, char[] password) {
        logout();

        // A malformed username cannot name an account: reject and log it.
        if (!Validation.validUsername(username)) {
            recordSecurityEvent("LOGIN_VALIDATION_FAILURE", "<invalid>",
                    "Rejected login input: username must match "
                    + "[A-Za-z0-9]{3,32}");
            return LoginResult.failure();
        }
        // A blank or over-long password is rejected (and logged) but, for an
        // existing account, still counts as a failed attempt toward lockout
        // and updates the last-attempt time and status. It is never hashed:
        // a fixed placeholder keeps the timing the same without spending
        // work on oversized input.
        boolean lengthOk = Validation.validCredentialLength(password);
        char[] checked = lengthOk ? password : LENGTH_PLACEHOLDER.clone();

        String timestamp = timestamp();
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                if (!lengthOk) {
                    insertLog(conn, "LOGIN_VALIDATION_FAILURE", username,
                            "Rejected login input: password length must "
                            + "be 1-128 characters", timestamp);
                }
                int id;
                String accountName;
                String storedPassword;
                int role;
                int locked;
                int failedAttempts;
                String previousAttemptAt;
                String previousStatus;
                String lastSuccessfulLogin;

                try (PreparedStatement statement = conn.prepareStatement(
                        "SELECT id, username, password, role, locked, "
                        + "failed_attempts, last_login_attempt_at, "
                        + "last_login_status, last_successful_login_at "
                        + "FROM users WHERE username = ? COLLATE NOCASE")) {
                    statement.setString(1, username);
                    try (ResultSet rs = statement.executeQuery()) {
                        if (!rs.next()) {
                            // Same work as a real check: no timing leak.
                            verifyAgainstDummy(checked);
                            insertLog(conn, "LOGIN_FAILURE", username,
                                    "Invalid credentials", timestamp);
                            conn.commit();
                            return LoginResult.failure();
                        }
                        id = rs.getInt("id");
                        accountName = rs.getString("username");
                        storedPassword = rs.getString("password");
                        role = rs.getInt("role");
                        locked = rs.getInt("locked");
                        failedAttempts = rs.getInt("failed_attempts");
                        previousAttemptAt =
                                rs.getString("last_login_attempt_at");
                        previousStatus = rs.getString("last_login_status");
                        lastSuccessfulLogin =
                                rs.getString("last_successful_login_at");
                    }
                }

                if (role < 2 || role > 5 || locked != 0) {
                    verifyAgainstDummy(checked);
                    updateLoginStatus(conn, id, timestamp, "BLOCKED");
                    insertLog(conn, "LOGIN_BLOCKED", accountName,
                            "Login rejected for a disabled or locked account",
                            timestamp);
                    conn.commit();
                    return LoginResult.failure();
                }

                boolean matches;
                if (!lengthOk) {
                    verifyAgainstDummy(checked);
                    matches = false;
                } else if (PasswordHasher.isHash(storedPassword)) {
                    matches = PasswordHasher.verify(password, storedPassword);
                } else {
                    // Fail closed: only salted hashes are ever accepted.
                    verifyAgainstDummy(password);
                    matches = false;
                    insertLog(conn, "CREDENTIAL_INTEGRITY_FAILURE",
                            accountName,
                            "Stored password is not a valid salted hash; "
                            + "login denied", timestamp);
                }

                if (!matches) {
                    int nextAttempts = failedAttempts + 1;
                    boolean lockAccount = nextAttempts >= MAX_FAILED_ATTEMPTS;
                    recordFailedAttempt(conn, id, nextAttempts, lockAccount,
                            timestamp, true);
                    insertLog(conn, "LOGIN_FAILURE", accountName,
                            "Invalid credentials; consecutive failed attempt "
                            + nextAttempts + " of " + MAX_FAILED_ATTEMPTS,
                            timestamp);
                    if (lockAccount) {
                        insertLog(conn, "ACCOUNT_LOCKED", accountName,
                                "Account disabled (role 1) after five "
                                + "consecutive failed login attempts",
                                timestamp);
                    }
                    conn.commit();
                    return LoginResult.failure();
                }

                try (PreparedStatement statement = conn.prepareStatement(
                        "UPDATE users SET failed_attempts = 0, "
                        + "last_login_attempt_at = ?, "
                        + "last_login_status = 'SUCCESS', "
                        + "last_successful_login_at = ? WHERE id = ?")) {
                    statement.setString(1, timestamp);
                    statement.setString(2, timestamp);
                    statement.setInt(3, id);
                    statement.executeUpdate();
                }
                insertLog(conn, "LOGIN_SUCCESS", accountName,
                        "Successful login", timestamp);
                conn.commit();
                session = new AuthenticatedUser(id, accountName, role);
                return LoginResult.success(previousAttemptAt, previousStatus,
                        lastSuccessfulLogin, failedAttempts);
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException | IllegalStateException ex) {
            throw fatalException("Authentication could not be completed.",
                    ex);
        }
    }

    private void verifyAgainstDummy(char[] password) {
        PasswordHasher.verify(password, dummyHash);
    }

    /** Failed login: also records the attempt's time and status. */
    private static final String RECORD_FAILED_LOGIN_SQL =
            "UPDATE users SET failed_attempts = ?, "
            + "locked = CASE WHEN ? = 1 THEN 1 ELSE locked END, "
            + "role_before_lock = CASE WHEN ? = 1 AND role BETWEEN 2 "
            + "AND 5 THEN role ELSE role_before_lock END, "
            + "role = CASE WHEN ? = 1 THEN 1 ELSE role END, "
            + "last_login_attempt_at = ?, last_login_status = ? "
            + "WHERE id = ?";

    /** Failed re-authentication: counts toward the same lockout. */
    private static final String RECORD_FAILED_REAUTH_SQL =
            "UPDATE users SET failed_attempts = ?, "
            + "locked = CASE WHEN ? = 1 THEN 1 ELSE locked END, "
            + "role_before_lock = CASE WHEN ? = 1 AND role BETWEEN 2 "
            + "AND 5 THEN role ELSE role_before_lock END, "
            + "role = CASE WHEN ? = 1 THEN 1 ELSE role END "
            + "WHERE id = ?";

    private static void recordFailedAttempt(
            Connection conn, int userId, int attempts, boolean lockAccount,
            String timestamp, boolean loginAttempt) throws SQLException {
        int lock = lockAccount ? 1 : 0;
        try (PreparedStatement statement = conn.prepareStatement(
                loginAttempt ? RECORD_FAILED_LOGIN_SQL
                        : RECORD_FAILED_REAUTH_SQL)) {
            int index = 1;
            statement.setInt(index++, attempts);
            statement.setInt(index++, lock);
            statement.setInt(index++, lock);
            statement.setInt(index++, lock);
            if (loginAttempt) {
                statement.setString(index++, timestamp);
                statement.setString(index++,
                        lockAccount ? "LOCKED" : "FAILURE");
            }
            statement.setInt(index, userId);
            statement.executeUpdate();
        }
    }

    private static void updateLoginStatus(
            Connection conn, int userId, String time, String status)
            throws SQLException {
        try (PreparedStatement statement = conn.prepareStatement(
                "UPDATE users SET last_login_attempt_at = ?, "
                + "last_login_status = ? WHERE id = ?")) {
            statement.setString(1, time);
            statement.setString(2, status);
            statement.setInt(3, userId);
            statement.executeUpdate();
        }
    }

    /**
     * Re-authentication before a critical operation. Wrong passwords count
     * toward the same five-attempt lockout as the login screen.
     */
    private void requireReauthentication(
            AuthenticatedUser user, char[] currentPassword, String operation) {
        String timestamp = timestamp();
        boolean signOut = false;
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                String stored;
                int role;
                int locked;
                int failedAttempts;
                try (PreparedStatement statement = conn.prepareStatement(
                        "SELECT password, role, locked, failed_attempts "
                        + "FROM users WHERE id = ?")) {
                    statement.setInt(1, user.id);
                    try (ResultSet rs = statement.executeQuery()) {
                        if (!rs.next()) {
                            stored = null;
                            role = 0;
                            locked = 1;
                            failedAttempts = 0;
                        } else {
                            stored = rs.getString("password");
                            role = rs.getInt("role");
                            locked = rs.getInt("locked");
                            failedAttempts = rs.getInt("failed_attempts");
                        }
                    }
                }
                if (stored == null || role != user.role || locked != 0) {
                    insertLog(conn, "SESSION_REVOKED", user.username,
                            "Session ended: account changed before "
                            + operation, timestamp);
                    conn.commit();
                    session = null;
                    throw new AccessDeniedException(DENIED_MESSAGE);
                }

                boolean verified =
                        Validation.validCredentialLength(currentPassword)
                        && PasswordHasher.verify(currentPassword, stored);
                if (verified) {
                    if (failedAttempts != 0) {
                        recordFailedAttempt(conn, user.id, 0, false,
                                timestamp, false);
                    }
                    insertLog(conn, "REAUTHENTICATION_SUCCESS",
                            user.username,
                            "Re-authenticated before " + operation,
                            timestamp);
                    conn.commit();
                    return;
                }

                int nextAttempts = failedAttempts + 1;
                boolean lockAccount = nextAttempts >= MAX_FAILED_ATTEMPTS;
                recordFailedAttempt(conn, user.id, nextAttempts, lockAccount,
                        timestamp, false);
                insertLog(conn, "REAUTHENTICATION_FAILURE", user.username,
                        "Re-authentication failed before " + operation
                        + "; consecutive failed attempt " + nextAttempts
                        + " of " + MAX_FAILED_ATTEMPTS, timestamp);
                if (lockAccount) {
                    insertLog(conn, "ACCOUNT_LOCKED", user.username,
                            "Account disabled (role 1) after five "
                            + "consecutive failed re-authentication attempts",
                            timestamp);
                    insertLog(conn, "SESSION_REVOKED", user.username,
                            "Session ended after account lockout",
                            timestamp);
                }
                conn.commit();
                signOut = lockAccount;
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException | IllegalStateException ex) {
            throw fatalException("Re-authentication could not be completed.",
                    ex);
        }
        if (signOut) {
            session = null;
            throw new AccessDeniedException(
                    "Re-authentication failed too many times. "
                    + "You have been signed out.");
        }
        throw new ValidationException("The current password is incorrect.");
    }

    // ------------------------------------------------------------------
    // Session and central authorization
    // ------------------------------------------------------------------

    public synchronized void logout() {
        AuthenticatedUser previous = session;
        session = null;
        if (previous != null) {
            recordSecurityEvent("LOGOUT", previous.username,
                    "User logged out");
        }
    }

    /** Ends the session after the idle timeout. */
    public synchronized void expireSession(int idleMinutes) {
        AuthenticatedUser previous = session;
        session = null;
        if (previous != null) {
            recordSecurityEvent("SESSION_TIMEOUT", previous.username,
                    "Session ended after " + idleMinutes
                    + " minutes of inactivity");
        }
    }

    public void setFatalErrorHandler(Runnable handler) {
        fatalErrorHandler = handler;
    }

    public synchronized void invalidateSession() {
        session = null;
    }

    /**
     * Re-reads the session's account so that role changes, locks and
     * deletions take effect on the very next request.
     */
    private synchronized AuthenticatedUser refreshSession() {
        AuthenticatedUser current = session;
        if (current == null) {
            return null;
        }
        String revokedReason = null;
        try (Connection conn = connect();
                PreparedStatement statement = conn.prepareStatement(
                        "SELECT role, locked FROM users "
                        + "WHERE id = ? AND username = ?")) {
            statement.setInt(1, current.id);
            statement.setString(2, current.username);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    revokedReason = "Session ended: account was deleted";
                } else {
                    int role = rs.getInt("role");
                    int locked = rs.getInt("locked");
                    if (role < 2 || role > 5 || locked != 0) {
                        revokedReason = "Session ended: account was disabled";
                    } else if (role != current.role) {
                        current = new AuthenticatedUser(
                                current.id, current.username, role);
                        session = current;
                    }
                }
            }
        } catch (SQLException ex) {
            throw fatalException(
                    "Account authorization could not be verified.", ex);
        }
        if (revokedReason != null) {
            session = null;
            recordSecurityEvent("SESSION_REVOKED", current.username,
                    revokedReason);
            return null;
        }
        return current;
    }

    /**
     * THE authorization gate for every controller operation: default deny,
     * and every denial is written to the security log.
     */
    private AuthenticatedUser authorize(Permission... permissions) {
        AuthenticatedUser current = refreshSession();
        if (current != null) {
            for (Permission permission : permissions) {
                if (AccessControl.isAllowed(current.role, permission)) {
                    return current;
                }
            }
        }
        recordSecurityEvent(
                "UNAUTHORIZED_OPERATION",
                current == null ? ANONYMOUS : current.username,
                "Denied operation '" + describe(permissions) + "' for "
                + (current == null ? "an unauthenticated user"
                        : "role " + current.role));
        throw new AccessDeniedException(DENIED_MESSAGE);
    }

    /**
     * Authorization check for UI panels and buttons. Returns false (and logs
     * an access-control violation) when the current role may not open it.
     */
    public boolean authorizeView(Permission permission, String resource) {
        AuthenticatedUser current = refreshSession();
        if (current != null
                && AccessControl.isAllowed(current.role, permission)) {
            return true;
        }
        recordSecurityEvent(
                "ACCESS_VIOLATION",
                current == null ? ANONYMOUS : current.username,
                "Blocked attempt to open " + resource + " ("
                + permission.getDescription() + ") by "
                + (current == null ? "an unauthenticated user"
                        : "role " + current.role));
        return false;
    }

    /** Visibility check (no logging): may the current user see this? */
    public boolean canAccess(Permission permission) {
        AuthenticatedUser current = refreshSession();
        return current != null
                && AccessControl.isAllowed(current.role, permission);
    }

    public int getAuthenticatedRole() {
        AuthenticatedUser current = refreshSession();
        return current == null ? 0 : current.role;
    }

    /** Records an unexpected error that the UI handled safely. */
    public void recordUnexpectedError(String errorType) {
        try {
            AuthenticatedUser current = session;
            recordSecurityEvent("UNEXPECTED_ERROR",
                    current == null ? ANONYMOUS : current.username,
                    "Unexpected application error handled safely ("
                    + (errorType == null ? "unknown"
                            : errorType.replaceAll("[^A-Za-z0-9_]", ""))
                    + "); session ended");
        } catch (RuntimeException ignored) {
            // Logging must never cause a second failure.
        }
    }

    private static String describe(Permission... permissions) {
        StringBuilder text = new StringBuilder();
        for (Permission permission : permissions) {
            if (text.length() > 0) {
                text.append(" / ");
            }
            text.append(permission.getDescription());
        }
        return text.toString();
    }

    // ------------------------------------------------------------------
    // Logging helpers
    // ------------------------------------------------------------------

    private static String timestamp() {
        return Instant.now().toString();
    }

    private static void insertLog(
            Connection conn, String event, String username,
            String description, String timestamp) throws SQLException {
        try (PreparedStatement statement = conn.prepareStatement(
                "INSERT INTO logs(event,username,desc,timestamp) "
                + "VALUES(?,?,?,?)")) {
            statement.setString(1, event);
            statement.setString(2, username == null ? ANONYMOUS : username);
            statement.setString(3, description);
            statement.setString(4, timestamp);
            statement.executeUpdate();
        }
    }

    private void recordSecurityEvent(
            String event, String username, String description) {
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                insertLog(conn, event, username, description, timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw fatalException("Security event could not be recorded.", ex);
        }
    }

    /** Logs a rejected input; the reason is fixed text, never the input. */
    private void rejectInput(String operation, ValidationException ex) {
        AuthenticatedUser current = session;
        recordSecurityEvent(
                "VALIDATION_FAILURE",
                current == null ? ANONYMOUS : current.username,
                "Rejected input for operation: " + operation
                + " (" + ex.getMessage() + ")");
    }

    /**
     * A business-rule rejection found inside a transaction: undoes the
     * transaction, records VALIDATION_FAILURE with a timestamp on the same
     * connection, commits the log entry and returns the exception to throw.
     */
    private static ValidationException rejectInTransaction(Connection conn,
            String username, String operation, String message)
            throws SQLException {
        conn.rollback();
        insertLog(conn, "VALIDATION_FAILURE", username,
                "Rejected input for operation: " + operation + " ("
                + message + ")", timestamp());
        conn.commit();
        return new ValidationException(message);
    }

    private AppException fatalException(String message, Throwable cause) {
        invalidateSession();
        Runnable handler = fatalErrorHandler;
        if (handler != null) {
            handler.run();
        }
        return new AppException(message, true, cause);
    }

    // ------------------------------------------------------------------
    // Products
    // ------------------------------------------------------------------

    public ArrayList<Product> getProduct() {
        authorize(Permission.VIEW_PRODUCTS);
        ArrayList<Product> products = new ArrayList<Product>();
        try (Connection conn = connect();
                PreparedStatement statement = conn.prepareStatement(
                        "SELECT id, name, stock, price FROM product "
                        + "ORDER BY id");
                ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                products.add(new Product(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getInt("stock"),
                        storedPriceCents(rs.getDouble("price"))));
            }
            return products;
        } catch (SQLException ex) {
            throw new AppException("Products could not be loaded.", false, ex);
        }
    }

    public void addProduct(String name, String stock, String price) {
        AuthenticatedUser user = authorize(Permission.ADD_PRODUCT);
        int parsedStock;
        long parsedPrice;
        try {
            Validation.productName(name);
            parsedStock = Validation.integer(stock, 0, Validation.MAX_STOCK);
            parsedPrice = Validation.price(price);
        } catch (ValidationException ex) {
            rejectInput("add-product", ex);
            throw ex;
        }

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                if (productExists(conn, name, null)) {
                    throw rejectInTransaction(conn, user.username,
                            "add-product",
                            "A product with that name already exists.");
                }
                try (PreparedStatement statement = conn.prepareStatement(
                        "INSERT INTO product(name,stock,price) "
                        + "VALUES(?,?,?)")) {
                    statement.setString(1, name);
                    statement.setInt(2, parsedStock);
                    statement.setDouble(3, parsedPrice / 100.0);
                    statement.executeUpdate();
                }
                insertLog(conn, "PRODUCT_CREATED", user.username,
                        "Product created", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("PRODUCT_CREATE_FAILURE", user.username,
                    "Product creation failed");
            throw new AppException("Product could not be added.", false, ex);
        }
    }

    public void updateProduct(
            String originalName, String name, String stock, String price) {
        AuthenticatedUser user = authorize(Permission.EDIT_PRODUCT);
        int parsedStock;
        long parsedPrice;
        try {
            Validation.productName(originalName);
            Validation.productName(name);
            parsedStock = Validation.integer(stock, 0, Validation.MAX_STOCK);
            parsedPrice = Validation.price(price);
        } catch (ValidationException ex) {
            rejectInput("edit-product", ex);
            throw ex;
        }

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                if (productExists(conn, name, originalName)) {
                    throw rejectInTransaction(conn, user.username,
                            "edit-product",
                            "A product with that name already exists.");
                }
                try (PreparedStatement statement = conn.prepareStatement(
                        "UPDATE product SET name = ?, stock = ?, price = ? "
                        + "WHERE name = ?")) {
                    statement.setString(1, name);
                    statement.setInt(2, parsedStock);
                    statement.setDouble(3, parsedPrice / 100.0);
                    statement.setString(4, originalName);
                    if (statement.executeUpdate() != 1) {
                        throw rejectInTransaction(conn, user.username,
                                "edit-product", "Product no longer exists.");
                    }
                }
                insertLog(conn, "PRODUCT_UPDATED", user.username,
                        "Product updated", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("PRODUCT_EDIT_FAILURE", user.username,
                    "Product update failed");
            throw new AppException("Product could not be updated.", false, ex);
        }
    }

    public void deleteProduct(String name) {
        AuthenticatedUser user = authorize(Permission.DELETE_PRODUCT);
        try {
            Validation.productName(name);
        } catch (ValidationException ex) {
            rejectInput("delete-product", ex);
            throw ex;
        }

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                int productId = -1;
                try (PreparedStatement find = conn.prepareStatement(
                        "SELECT id FROM product WHERE name = ?")) {
                    find.setString(1, name);
                    try (ResultSet rs = find.executeQuery()) {
                        if (rs.next()) {
                            productId = rs.getInt("id");
                        }
                    }
                }
                if (productId < 0) {
                    throw rejectInTransaction(conn, user.username,
                            "delete-product", "Product no longer exists.");
                }
                try (PreparedStatement findHistory = conn.prepareStatement(
                        "SELECT 1 FROM history WHERE product_id = ? "
                        + "OR (product_id IS NULL AND name = ?) LIMIT 1")) {
                    findHistory.setInt(1, productId);
                    findHistory.setString(2, name);
                    try (ResultSet rs = findHistory.executeQuery()) {
                        if (rs.next()) {
                            insertLog(conn, "PRODUCT_DELETE_REJECTED",
                                    user.username,
                                    "Product is referenced by purchase "
                                    + "history", timestamp());
                            conn.commit();
                            throw new ValidationException(
                                    "Product with purchase history cannot "
                                    + "be deleted.");
                        }
                    }
                }
                try (PreparedStatement delete = conn.prepareStatement(
                        "DELETE FROM product WHERE id = ?")) {
                    delete.setInt(1, productId);
                    delete.executeUpdate();
                }
                insertLog(conn, "PRODUCT_DELETED", user.username,
                        "Product deleted", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("PRODUCT_DELETE_FAILURE", user.username,
                    "Product deletion failed");
            throw new AppException("Product could not be deleted.", false, ex);
        }
    }

    public long purchaseProduct(String productName, String quantity) {
        AuthenticatedUser user = authorize(Permission.PURCHASE_PRODUCT);
        int parsedQuantity;
        try {
            Validation.productName(productName);
            parsedQuantity = Validation.integer(
                    quantity, 1, Validation.MAX_STOCK);
        } catch (ValidationException ex) {
            rejectInput("purchase-product", ex);
            throw ex;
        }

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                int productId;
                int stock;
                long priceCents;
                try (PreparedStatement find = conn.prepareStatement(
                        "SELECT id, stock, price FROM product WHERE name = ?")) {
                    find.setString(1, productName);
                    try (ResultSet rs = find.executeQuery()) {
                        if (!rs.next()) {
                            insertLog(conn, "PURCHASE_REJECTED", user.username,
                                    "Requested product was not found",
                                    timestamp());
                            conn.commit();
                            throw new ValidationException(
                                    "Product no longer exists.");
                        }
                        productId = rs.getInt("id");
                        stock = rs.getInt("stock");
                        priceCents = storedPriceCents(rs.getDouble("price"));
                    }
                }

                if (stock < parsedQuantity) {
                    insertLog(conn, "PURCHASE_REJECTED", user.username,
                            "Insufficient product stock", timestamp());
                    conn.commit();
                    throw new ValidationException(
                            "There is not enough stock to complete the "
                            + "purchase.");
                }

                long totalCents = Math.multiplyExact(
                        priceCents, (long) parsedQuantity);
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE product SET stock = stock - ? "
                        + "WHERE id = ? AND stock >= ?")) {
                    update.setInt(1, parsedQuantity);
                    update.setInt(2, productId);
                    update.setInt(3, parsedQuantity);
                    if (update.executeUpdate() != 1) {
                        throw new SQLException(
                                "Product stock changed during purchase.");
                    }
                }
                try (PreparedStatement insert = conn.prepareStatement(
                        "INSERT INTO history(username,name,stock,timestamp,"
                        + "user_id,product_id,unit_price_cents) "
                        + "VALUES(?,?,?,?,?,?,?)")) {
                    insert.setString(1, user.username);
                    insert.setString(2, productName);
                    insert.setInt(3, parsedQuantity);
                    insert.setString(4, timestamp());
                    insert.setInt(5, user.id);
                    insert.setInt(6, productId);
                    insert.setLong(7, priceCents);
                    insert.executeUpdate();
                }
                insertLog(conn, "PURCHASE_COMPLETED", user.username,
                        "Product purchase completed", timestamp());
                conn.commit();
                return totalCents;
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("PURCHASE_FAILURE", user.username,
                    "Purchase could not be completed");
            throw new AppException("Purchase could not be completed.", false,
                    ex);
        }
    }

    private static boolean productExists(
            Connection conn, String name, String exceptName)
            throws SQLException {
        try (PreparedStatement statement = conn.prepareStatement(
                "SELECT name FROM product WHERE name = ? COLLATE NOCASE")) {
            statement.setString(1, name);
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    if (exceptName == null
                            || !exceptName.equals(rs.getString("name"))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Converts a stored REAL price to cents without trusting its range. */
    private static long storedPriceCents(double price) {
        if (Double.isNaN(price) || Double.isInfinite(price) || price < 0
                || price > Validation.MAX_PRICE_CENTS / 100.0) {
            return 0;
        }
        return BigDecimal.valueOf(price)
                .setScale(2, RoundingMode.HALF_UP)
                .movePointRight(2)
                .longValueExact();
    }

    // ------------------------------------------------------------------
    // Purchase history
    // ------------------------------------------------------------------

    /** Manager view: every user's purchases. */
    private static final String ALL_HISTORY_SQL =
            "SELECT id, user_id, product_id, username, name, "
            + "stock, unit_price_cents, timestamp FROM history "
            + "ORDER BY timestamp DESC, id DESC";

    /** Client view: only the session's own purchases. */
    private static final String OWN_HISTORY_SQL =
            "SELECT id, user_id, product_id, username, name, "
            + "stock, unit_price_cents, timestamp FROM history "
            + "WHERE user_id = ? OR (user_id IS NULL "
            + "AND username = ? COLLATE NOCASE) "
            + "ORDER BY timestamp DESC, id DESC";

    public ArrayList<History> getHistory() {
        AuthenticatedUser user = authorize(
                Permission.VIEW_OWN_HISTORY, Permission.VIEW_ALL_HISTORY);
        boolean ownHistoryOnly = !AccessControl.isAllowed(
                user.role, Permission.VIEW_ALL_HISTORY);
        String sql = ownHistoryOnly ? OWN_HISTORY_SQL : ALL_HISTORY_SQL;
        ArrayList<History> histories = new ArrayList<History>();
        try (Connection conn = connect();
                PreparedStatement statement = conn.prepareStatement(sql)) {
            if (ownHistoryOnly) {
                statement.setInt(1, user.id);
                statement.setString(2, user.username);
            }
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    Integer userId = getNullableInt(rs, "user_id");
                    Integer productId = getNullableInt(rs, "product_id");
                    long unitPrice = rs.getLong("unit_price_cents");
                    Long price = rs.wasNull() ? null : Long.valueOf(unitPrice);
                    histories.add(new History(
                            rs.getInt("id"),
                            userId == null ? 0 : userId,
                            productId == null ? 0 : productId,
                            rs.getString("username"),
                            rs.getString("name"),
                            rs.getInt("stock"),
                            price,
                            rs.getString("timestamp")));
                }
            }
            return histories;
        } catch (SQLException ex) {
            throw new AppException("Purchase history could not be loaded.",
                    false, ex);
        }
    }

    public ArrayList<History> searchHistory(String query) {
        authorize(Permission.VIEW_OWN_HISTORY, Permission.VIEW_ALL_HISTORY);
        try {
            Validation.search(query);
        } catch (ValidationException ex) {
            rejectInput("search-history", ex);
            throw ex;
        }

        // Usernames: whole name, any case. Product names: any part of the
        // name, any case ("firefox" and "fire" both find "Firefox").
        String needle = query.toLowerCase(Locale.ROOT);
        ArrayList<History> matches = new ArrayList<History>();
        for (History entry : getHistory()) {
            String product = entry.getName().toLowerCase(Locale.ROOT);
            if (entry.getUsername().equalsIgnoreCase(query)
                    || needle.contains(product)
                    || product.contains(needle)) {
                matches.add(entry);
            }
        }
        return matches;
    }

    // ------------------------------------------------------------------
    // Security logs
    // ------------------------------------------------------------------

    public ArrayList<Logs> getLogs() {
        authorize(Permission.VIEW_LOGS);
        ArrayList<Logs> logs = new ArrayList<Logs>();
        try (Connection conn = connect();
                PreparedStatement statement = conn.prepareStatement(
                        "SELECT id, event, username, desc, timestamp "
                        + "FROM logs WHERE archived = 0 "
                        + "ORDER BY timestamp DESC, id DESC");
                ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                logs.add(new Logs(
                        rs.getInt("id"),
                        rs.getString("event"),
                        rs.getString("username"),
                        rs.getString("desc"),
                        rs.getString("timestamp")));
            }
            return logs;
        } catch (SQLException ex) {
            throw new AppException("Security logs could not be loaded.",
                    false, ex);
        }
    }

    /**
     * "Clear" for the administrator: entries are hidden from the log view
     * but RETAINED (append-only audit trail); nothing is ever deleted.
     */
    public int archiveLogs() {
        AuthenticatedUser user = authorize(Permission.ARCHIVE_LOGS);
        String timestamp = timestamp();
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                int archived;
                try (PreparedStatement statement = conn.prepareStatement(
                        "UPDATE logs SET archived = 1, archived_at = ?, "
                        + "archived_by = ? WHERE archived = 0")) {
                    statement.setString(1, timestamp);
                    statement.setString(2, user.username);
                    archived = statement.executeUpdate();
                }
                insertLog(conn, "SECURITY_LOGS_ARCHIVED", user.username,
                        "Administrator archived " + archived
                        + " log entries (retained for audit)", timestamp);
                conn.commit();
                return archived;
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw new AppException("Security logs could not be archived.",
                    false, ex);
        }
    }

    // ------------------------------------------------------------------
    // User management
    // ------------------------------------------------------------------

    /** Self-registration: always creates a Client (role 2). */
    public void addUser(
            String username, char[] password, char[] confirmation) {
        createUser(null, username, password, confirmation,
                AccessControl.CLIENT);
    }

    /** Administrator-created account (roles 2-4 only). */
    public void addUser(String username, char[] password,
            char[] confirmation, int role) {
        AuthenticatedUser user = authorize(Permission.ADD_USER);
        if (!AccessControl.isAssignableOnCreate(role)) {
            recordSecurityEvent("UNAUTHORIZED_OPERATION", user.username,
                    "Denied creating an account with role " + role);
            throw new AccessDeniedException(DENIED_MESSAGE);
        }
        createUser(user, username, password, confirmation, role);
    }

    private void createUser(AuthenticatedUser admin, String username,
            char[] password, char[] confirmation, int role) {
        String operation = admin == null ? "register" : "add-user";
        try {
            Validation.username(username);
            Validation.password(password, confirmation);
            Validation.role(role);
        } catch (ValidationException ex) {
            rejectInput(operation, ex);
            throw ex;
        }

        String actor = admin == null ? username : admin.username;
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                if (admin != null && findAccount(conn, username) != null) {
                    throw rejectInTransaction(conn, admin.username,
                            "add-user", "That username is already taken.");
                }
                try (PreparedStatement statement = conn.prepareStatement(
                        "INSERT INTO users(username,password,role) "
                        + "VALUES(?,?,?)")) {
                    statement.setString(1, username);
                    statement.setString(2, PasswordHasher.hash(password));
                    statement.setInt(3, role);
                    statement.executeUpdate();
                }
                insertLog(conn,
                        admin == null ? "USER_REGISTERED"
                                : "USER_CREATED_BY_ADMIN",
                        actor,
                        admin == null ? "New client account registered"
                                : "Administrator created an account with "
                                + "role " + role,
                        timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    admin == null ? "USER_REGISTRATION_FAILURE"
                            : "USER_CREATION_FAILURE",
                    actor, "Account creation failed");
            throw new AppException(
                    admin == null ? "Registration could not be completed."
                            : "User creation could not be completed.",
                    false, ex);
        }
    }

    public ArrayList<User> getUsers() {
        authorize(Permission.VIEW_USERS);
        ArrayList<User> users = new ArrayList<User>();
        try (Connection conn = connect();
                PreparedStatement statement = conn.prepareStatement(
                        "SELECT id, username, role, locked, failed_attempts "
                        + "FROM users ORDER BY id");
                ResultSet rs = statement.executeQuery()) {
            while (rs.next()) {
                users.add(new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getInt("role"),
                        rs.getInt("locked"),
                        rs.getInt("failed_attempts")));
            }
            return users;
        } catch (SQLException ex) {
            throw new AppException("Users could not be loaded.", false, ex);
        }
    }

    public void updateUserRole(
            String username, int role, char[] currentPassword) {
        AuthenticatedUser user = authorize(Permission.EDIT_USER_ROLE);
        validateUserName(username, "edit-user-role");
        try {
            Validation.role(role);
        } catch (ValidationException ex) {
            rejectInput("edit-user-role", ex);
            throw ex;
        }
        if (!AccessControl.isAssignableOnEdit(role)) {
            recordSecurityEvent("UNAUTHORIZED_OPERATION", user.username,
                    "Denied assigning role " + role
                    + " (administrators may assign roles 1-4 only)");
            throw new AccessDeniedException(DENIED_MESSAGE);
        }
        requireReauthentication(user, currentPassword, "changing a role");

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                Account target = requireManageableTarget(
                        conn, user, username, "USER_ROLE_CHANGE_REJECTED");
                Integer roleBeforeLock = role == AccessControl.DISABLED
                        ? (target.locked == 0 && target.role >= 2
                                ? Integer.valueOf(target.role)
                                : target.roleBeforeLock)
                        : null;
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE users SET role = ?, locked = ?, "
                        + "role_before_lock = ?, failed_attempts = 0 "
                        + "WHERE id = ?")) {
                    update.setInt(1, role);
                    update.setInt(2, role == AccessControl.DISABLED ? 1 : 0);
                    setNullableInt(update, 3, roleBeforeLock);
                    update.setInt(4, target.id);
                    update.executeUpdate();
                }
                insertLog(conn, "USER_ROLE_CHANGED", user.username,
                        "Account role changed from " + target.role + " to "
                        + role, timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("USER_ROLE_CHANGE_FAILURE", user.username,
                    "Account role change failed");
            throw new AppException("User role could not be changed.", false,
                    ex);
        }
    }

    public void setUserLocked(String username, boolean locked) {
        AuthenticatedUser user = authorize(
                locked ? Permission.LOCK_USER : Permission.UNLOCK_USER);
        validateUserName(username, locked ? "lock-user" : "unlock-user");
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                Account target = requireManageableTarget(
                        conn, user, username, "ACCOUNT_LOCK_CHANGE_REJECTED");
                if ((locked ? 1 : 0) == target.locked) {
                    conn.rollback();
                    return;
                }
                if (!locked && target.roleBeforeLock == null) {
                    throw rejectInTransaction(conn, user.username,
                            "unlock-user",
                            "The original role is not recorded. Use Edit "
                            + "Role to choose the account's role instead.");
                }
                int resultingRole = locked ? AccessControl.DISABLED
                        : target.roleBeforeLock.intValue();
                Integer resultingRoleBeforeLock =
                        locked && target.role >= 2 && target.role <= 4
                                ? Integer.valueOf(target.role) : null;
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE users SET locked = ?, role = ?, "
                        + "role_before_lock = ?, failed_attempts = 0 "
                        + "WHERE id = ?")) {
                    update.setInt(1, locked ? 1 : 0);
                    update.setInt(2, resultingRole);
                    setNullableInt(update, 3, resultingRoleBeforeLock);
                    update.setInt(4, target.id);
                    update.executeUpdate();
                }
                insertLog(conn, locked ? "ACCOUNT_LOCKED" : "ACCOUNT_UNLOCKED",
                        user.username,
                        locked ? "Administrator disabled an account"
                                : "Administrator re-enabled an account",
                        timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    locked ? "ACCOUNT_LOCK_FAILURE" : "ACCOUNT_UNLOCK_FAILURE",
                    user.username, "Account lock status could not be changed");
            throw new AppException("Account lock status could not be changed.",
                    false, ex);
        }
    }

    public void changeUserPassword(
            String username, char[] currentPassword,
            char[] password, char[] confirmation) {
        AuthenticatedUser user = authorize(Permission.CHANGE_USER_PASSWORD);
        validateUserName(username, "change-user-password");
        try {
            Validation.password(password, confirmation);
        } catch (ValidationException ex) {
            rejectInput("change-user-password", ex);
            throw ex;
        }
        requireReauthentication(user, currentPassword,
                "changing a password");

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                Account target = findAccount(conn, username);
                if (target == null) {
                    throw rejectInTransaction(conn, user.username,
                            "change-user-password", "User no longer exists.");
                }
                // An administrator may change their OWN password, but not
                // another administrator's.
                if (target.id != user.id) {
                    requireManageableTarget(conn, user, username,
                            "USER_PASSWORD_CHANGE_REJECTED");
                }
                try (PreparedStatement statement = conn.prepareStatement(
                        "UPDATE users SET password = ?, failed_attempts = 0 "
                        + "WHERE id = ?")) {
                    statement.setString(1, PasswordHasher.hash(password));
                    statement.setInt(2, target.id);
                    statement.executeUpdate();
                }
                insertLog(conn, "USER_PASSWORD_CHANGED", user.username,
                        target.id == user.id
                                ? "Administrator changed their own password"
                                : "Administrator changed an account password",
                        timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("USER_PASSWORD_CHANGE_FAILURE", user.username,
                    "Account password change failed");
            throw new AppException("Password could not be changed.", false,
                    ex);
        }
    }

    public void deleteUser(String username, char[] currentPassword) {
        AuthenticatedUser user = authorize(Permission.DELETE_USER);
        validateUserName(username, "delete-user");
        requireReauthentication(user, currentPassword, "deleting a user");

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                Account target = requireManageableTarget(
                        conn, user, username, "USER_DELETE_REJECTED");
                try (PreparedStatement findHistory = conn.prepareStatement(
                        "SELECT 1 FROM history WHERE user_id = ? "
                        + "OR (user_id IS NULL AND username = ? "
                        + "COLLATE NOCASE) LIMIT 1")) {
                    findHistory.setInt(1, target.id);
                    findHistory.setString(2, target.username);
                    try (ResultSet rs = findHistory.executeQuery()) {
                        if (rs.next()) {
                            insertLog(conn, "USER_DELETE_REJECTED",
                                    user.username,
                                    "Account is referenced by purchase "
                                    + "history", timestamp());
                            conn.commit();
                            throw new ValidationException(
                                    "User with purchase history cannot be "
                                    + "deleted. Lock the account instead.");
                        }
                    }
                }
                try (PreparedStatement delete = conn.prepareStatement(
                        "DELETE FROM users WHERE id = ?")) {
                    delete.setInt(1, target.id);
                    delete.executeUpdate();
                }
                insertLog(conn, "USER_DELETED", user.username,
                        "Administrator deleted an account", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent("USER_DELETE_FAILURE", user.username,
                    "Account deletion failed");
            throw new AppException("User could not be deleted.", false, ex);
        }
    }

    /**
     * Loads the target account and enforces the "not a super admin" rules:
     * an administrator cannot modify their own account through user
     * management, nor any administrator account (including locked ones).
     * Rejections are logged on the same connection, then committed.
     */
    private Account requireManageableTarget(Connection conn,
            AuthenticatedUser admin, String username, String rejectEvent)
            throws SQLException {
        Account target = findAccount(conn, username);
        if (target == null) {
            throw rejectInTransaction(conn, admin.username, "manage-user",
                    "User no longer exists.");
        }
        if (target.id == admin.id || target.isAdministrator()) {
            insertLog(conn, rejectEvent, admin.username,
                    target.id == admin.id
                            ? "Administrator attempted to modify their own "
                            + "account through user management"
                            : "Administrator attempted to modify another "
                            + "administrator account", timestamp());
            conn.commit();
            throw new AccessDeniedException(target.id == admin.id
                    ? "You cannot modify your own account here."
                    : ADMIN_TARGET_MESSAGE);
        }
        return target;
    }

    private static Account findAccount(Connection conn, String username)
            throws SQLException {
        try (PreparedStatement find = conn.prepareStatement(
                "SELECT id, username, role, locked, role_before_lock "
                + "FROM users WHERE username = ? COLLATE NOCASE")) {
            find.setString(1, username);
            try (ResultSet rs = find.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return new Account(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getInt("role"),
                        rs.getInt("locked"),
                        getNullableInt(rs, "role_before_lock"));
            }
        }
    }

    private void validateUserName(String username, String operation) {
        try {
            Validation.username(username);
        } catch (ValidationException ex) {
            rejectInput(operation, ex);
            throw ex;
        }
    }

    // ------------------------------------------------------------------
    // JDBC helpers
    // ------------------------------------------------------------------

    private static Integer getNullableInt(ResultSet rs, String column)
            throws SQLException {
        int value = rs.getInt(column);
        return rs.wasNull() ? null : Integer.valueOf(value);
    }

    private static void setNullableInt(
            PreparedStatement statement, int index, Integer value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.INTEGER);
        } else {
            statement.setInt(index, value.intValue());
        }
    }

    private static void rollback(Connection conn, SQLException original) {
        try {
            conn.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
