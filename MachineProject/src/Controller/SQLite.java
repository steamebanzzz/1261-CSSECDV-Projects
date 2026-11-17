package Controller;

import Model.History;
import Model.LoginResult;
import Model.Logs;
import Model.Product;
import Model.User;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;

public class SQLite {

    public int DEBUG_MODE = 0;
    String driverURL = "jdbc:sqlite:" + "database.db";
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

    public SQLite() {
        initializeDatabase();
    }

    private void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (Statement statement = conn.createStatement()) {
                statement.execute("CREATE TABLE IF NOT EXISTS users ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "username TEXT NOT NULL UNIQUE,"
                        + "password TEXT NOT NULL,"
                        + "role INTEGER DEFAULT 2,"
                        + "locked INTEGER DEFAULT 0)");
                statement.execute("CREATE TABLE IF NOT EXISTS product ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "name TEXT NOT NULL UNIQUE,"
                        + "stock INTEGER DEFAULT 0,"
                        + "price REAL DEFAULT 0.00)");
                statement.execute("CREATE TABLE IF NOT EXISTS history ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "username TEXT NOT NULL,"
                        + "name TEXT NOT NULL,"
                        + "stock INTEGER DEFAULT 0,"
                        + "timestamp TEXT NOT NULL)");
                statement.execute("CREATE TABLE IF NOT EXISTS logs ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        + "event TEXT NOT NULL,"
                        + "username TEXT NOT NULL,"
                        + "desc TEXT NOT NULL,"
                        + "timestamp TEXT NOT NULL)");
            }

            addColumnIfMissing(
                    conn, "users", "failed_attempts",
                    "INTEGER NOT NULL DEFAULT 0");
            addColumnIfMissing(
                    conn, "users", "role_before_lock", "INTEGER");
            addColumnIfMissing(
                    conn, "users", "last_login_attempt_at", "TEXT");
            addColumnIfMissing(
                    conn, "users", "last_login_status", "TEXT");
            addColumnIfMissing(
                    conn, "users", "last_successful_login_at", "TEXT");
            addColumnIfMissing(conn, "history", "user_id", "INTEGER");
            addColumnIfMissing(conn, "history", "product_id", "INTEGER");
            addColumnIfMissing(
                    conn, "history", "unit_price_cents", "INTEGER");

            try (Statement statement = conn.createStatement()) {
                statement.executeUpdate(
                        "UPDATE users SET role_before_lock = role "
                        + "WHERE locked = 1 AND role BETWEEN 2 AND 5 "
                        + "AND role_before_lock IS NULL");
                statement.executeUpdate(
                        "UPDATE history SET user_id = ("
                        + "SELECT id FROM users WHERE "
                        + "users.username = history.username) "
                        + "WHERE user_id IS NULL");
                statement.executeUpdate(
                        "UPDATE history SET product_id = ("
                        + "SELECT id FROM product WHERE "
                        + "product.name = history.name) "
                        + "WHERE product_id IS NULL");
                statement.executeUpdate(
                        "UPDATE history SET unit_price_cents = ("
                        + "SELECT CAST(ROUND(price * 100) AS INTEGER) "
                        + "FROM product WHERE product.name = history.name) "
                        + "WHERE unit_price_cents IS NULL "
                        + "AND EXISTS (SELECT 1 FROM product "
                        + "WHERE product.name = history.name)");
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS "
                        + "history_user_id_idx ON history(user_id)");
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS "
                        + "history_product_id_idx ON history(product_id)");
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS "
                        + "logs_timestamp_idx ON logs(timestamp)");
            }
            conn.commit();
        } catch (SQLException ex) {
            throw fatalException(
                    "Database initialization could not be completed.", ex);
        }
    }

    private static void addColumnIfMissing(
            Connection conn, String table, String column, String definition)
            throws SQLException {

        boolean found = false;
        try (Statement statement = conn.createStatement();
                ResultSet columns =
                        statement.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (columns.next()) {
                if (column.equalsIgnoreCase(columns.getString("name"))) {
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            try (Statement statement = conn.createStatement()) {
                statement.execute(
                        "ALTER TABLE " + table + " ADD COLUMN "
                        + column + " " + definition);
            }
        }
    }

    public synchronized LoginResult login(
            String username, char[] password) {

        logout();
        if (!Validation.validUsername(username) || password == null) {
            recordSecurityEvent(
                    "LOGIN_VALIDATION_FAILURE",
                    Validation.validUsername(username)
                            ? username : "<invalid>",
                    "Rejected malformed login input");
            return new LoginResult(false, null, "FAILURE");
        }

        String timestamp = Instant.now().toString();
        String query = "SELECT id, password, role, locked, failed_attempts, "
                + "last_login_attempt_at, last_login_status, "
                + "last_successful_login_at "
                + "FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                int id;
                String storedPassword;
                int role;
                int locked;
                int failedAttempts;
                String previousAttemptAt;
                String previousStatus;
                String lastSuccessfulLogin;

                try (PreparedStatement statement =
                        conn.prepareStatement(query)) {
                    statement.setString(1, username);
                    try (ResultSet rs = statement.executeQuery()) {
                        if (!rs.next()) {
                            insertLog(conn, "LOGIN_FAILURE", username,
                                    "Invalid credentials", timestamp);
                            conn.commit();
                            return new LoginResult(
                                    false, null, "FAILURE");
                        }

                        id = rs.getInt("id");
                        storedPassword = rs.getString("password");
                        role = rs.getInt("role");
                        locked = rs.getInt("locked");
                        failedAttempts = rs.getInt("failed_attempts");
                        previousAttemptAt =
                                rs.getString("last_login_attempt_at");
                        previousStatus =
                                rs.getString("last_login_status");
                        lastSuccessfulLogin =
                                rs.getString("last_successful_login_at");
                    }
                }

                if (role < 2 || role > 5 || locked != 0) {
                    updateLoginStatus(
                            conn, id, timestamp, "BLOCKED");
                    insertLog(conn, "LOGIN_BLOCKED", username,
                            "Login rejected for a disabled or locked account",
                            timestamp);
                    conn.commit();
                    return new LoginResult(
                            false, null, "FAILURE");
                }

                boolean encodedHash =
                        PasswordHasher.isHash(storedPassword);
                boolean matches = encodedHash
                        ? PasswordHasher.verify(password, storedPassword)
                        : storedPassword != null
                                && !storedPassword.startsWith(
                                        "pbkdf2-sha256$")
                                && matchesLegacyPassword(
                                        password, storedPassword);

                if (!matches) {
                    int nextAttempts = failedAttempts + 1;
                    boolean lockAccount = nextAttempts >= 5;
                    String status = lockAccount ? "LOCKED" : "FAILURE";

                    String update = "UPDATE users SET failed_attempts = ?, "
                            + "locked = ?, "
                            + "role = CASE WHEN ? = 1 THEN 1 ELSE role END, "
                            + "role_before_lock = CASE "
                            + "WHEN ? = 1 AND role BETWEEN 2 AND 5 "
                            + "THEN role ELSE role_before_lock END, "
                            + "last_login_attempt_at = ?, "
                            + "last_login_status = ? WHERE id = ?";

                    try (PreparedStatement statement =
                            conn.prepareStatement(update)) {
                        statement.setInt(1, nextAttempts);
                        statement.setInt(2, lockAccount ? 1 : locked);
                        statement.setInt(3, lockAccount ? 1 : 0);
                        statement.setInt(4, lockAccount ? 1 : 0);
                        statement.setString(5, timestamp);
                        statement.setString(6, status);
                        statement.setInt(7, id);
                        statement.executeUpdate();
                    }

                    insertLog(conn, "LOGIN_FAILURE", username,
                            "Invalid credentials; failed attempt "
                                    + nextAttempts,
                            timestamp);

                    if (lockAccount) {
                        insertLog(conn, "ACCOUNT_LOCKED", username,
                                "Account locked after five failed login attempts",
                                timestamp);
                    }

                    conn.commit();
                    return new LoginResult(false, null, "FAILURE");
                }

                if (!encodedHash) {
                    String updatePassword =
                            "UPDATE users SET password = ? WHERE id = ?";
                    try (PreparedStatement statement =
                            conn.prepareStatement(updatePassword)) {
                        statement.setString(
                                1, PasswordHasher.hash(password));
                        statement.setInt(2, id);
                        statement.executeUpdate();
                    }
                }

                String updateLogin = "UPDATE users SET failed_attempts = 0, "
                        + "last_login_attempt_at = ?, "
                        + "last_login_status = 'SUCCESS', "
                        + "last_successful_login_at = ? WHERE id = ?";
                try (PreparedStatement statement =
                        conn.prepareStatement(updateLogin)) {
                    statement.setString(1, timestamp);
                    statement.setString(2, timestamp);
                    statement.setInt(3, id);
                    statement.executeUpdate();
                }
                insertLog(conn, "LOGIN_SUCCESS", username,
                        "Successful login", timestamp);
                conn.commit();
                session = new AuthenticatedUser(id, username, role);
                return new LoginResult(
                        true, previousAttemptAt, previousStatus,
                        lastSuccessfulLogin);
            } catch (SQLException ex) {
                conn.rollback();
                throw ex;
            }
        } catch (SQLException ex) {
            throw fatalException(
                    "Authentication could not be completed.", ex);
        }
    }

    public synchronized boolean authenticate(
            String username, char[] password) {
        return login(username, password).isSuccessful();
    }

    private static boolean matchesLegacyPassword(
            char[] password, String storedPassword) {

        byte[] entered = new String(password)
                .getBytes(StandardCharsets.UTF_8);
        byte[] stored = storedPassword.getBytes(StandardCharsets.UTF_8);

        try {
            return MessageDigest.isEqual(entered, stored);
        } finally {
            Arrays.fill(entered, (byte) 0);
            Arrays.fill(stored, (byte) 0);
        }
    }

    public synchronized int getAuthenticatedRole() {
        if (session == null) {
            return 0;
        }
        try {
            return requireRoles(
                    "read-session-role", 2, 3, 4, 5).role;
        } catch (SecurityException ex) {
            return 0;
        }
    }

    public synchronized void logout() {
        AuthenticatedUser previousSession = session;
        session = null;
        if (previousSession != null) {
            recordSecurityEvent(
                    "LOGOUT", previousSession.username,
                    "User logged out");
        }
    }

    public void setFatalErrorHandler(Runnable handler) {
        fatalErrorHandler = handler;
    }

    public synchronized void invalidateSession() {
        session = null;
    }

    private AppException fatalException(
            String message, Throwable cause) {
        invalidateSession();
        Runnable handler = fatalErrorHandler;
        if (handler != null) {
            handler.run();
        }
        return new AppException(message, true, cause);
    }

    private static long priceCents(double price) {
        if (Double.isNaN(price) || Double.isInfinite(price)
                || price < 0
                || price > Validation.MAX_PRICE_CENTS / 100.0) {
            throw new IllegalArgumentException(
                    "Price is outside the allowed range.");
        }
        return BigDecimal.valueOf(price)
                .setScale(2, RoundingMode.HALF_UP)
                .movePointRight(2)
                .longValueExact();
    }

    private static String timestamp() {
        return Instant.now().toString();
    }

    private static void insertLog(
            Connection conn, String event, String username,
            String description, String timestamp) throws SQLException {

        String sql =
                "INSERT INTO logs(event,username,desc,timestamp) VALUES(?,?,?,?)";
        try (PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.setString(1, event);
            statement.setString(
                    2, username == null ? "<anonymous>" : username);
            statement.setString(3, description);
            statement.setString(4, timestamp);
            statement.executeUpdate();
        }
    }

    private void recordSecurityEvent(
            String event, String username, String description) {

        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                insertLog(conn, event, username, description, timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw fatalException(
                    "Security event could not be recorded.", ex);
        }
    }

    private void updateLoginStatus(
            Connection conn, int userId, String time, String status)
            throws SQLException {

        String sql = "UPDATE users SET last_login_attempt_at = ?, "
                + "last_login_status = ? WHERE id = ?";
        try (PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.setString(1, time);
            statement.setString(2, status);
            statement.setInt(3, userId);
            statement.executeUpdate();
        }
    }

    private synchronized AuthenticatedUser requireRoles(
            String operation, int... allowedRoles) {

        AuthenticatedUser currentSession = session;
        String revocationDescription = null;
        String revokedUsername = null;
        if (currentSession != null) {
            String query = "SELECT role, locked FROM users "
                    + "WHERE id = ? AND username = ?";
            try (Connection conn = DriverManager.getConnection(driverURL);
                    PreparedStatement statement =
                            conn.prepareStatement(query)) {
                statement.setInt(1, currentSession.id);
                statement.setString(2, currentSession.username);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next()) {
                        int currentRole = rs.getInt("role");
                        int locked = rs.getInt("locked");
                        if (currentRole >= 2 && currentRole <= 5
                                && locked == 0) {
                            currentSession = new AuthenticatedUser(
                                    currentSession.id,
                                    currentSession.username,
                                    currentRole);
                            session = currentSession;
                        } else {
                            session = null;
                            revokedUsername = currentSession.username;
                            revocationDescription =
                                    "Session invalidated after account "
                                    + "permissions changed";
                            currentSession = null;
                        }
                    } else {
                        session = null;
                        revokedUsername = currentSession.username;
                        revocationDescription =
                                "Session invalidated after account deletion";
                        currentSession = null;
                    }
                }
            } catch (SQLException ex) {
                throw fatalException(
                        "Account authorization could not be verified.", ex);
            }
        }

        if (revocationDescription != null) {
            recordSecurityEvent(
                    "SESSION_REVOKED",
                    revokedUsername,
                    revocationDescription);
        }

        for (int allowedRole : allowedRoles) {
            if (currentSession != null
                    && currentSession.role == allowedRole) {
                return currentSession;
            }
        }

        recordSecurityEvent(
                "UNAUTHORIZED_OPERATION",
                currentSession == null ? "<anonymous>"
                        : currentSession.username,
                "Denied operation: " + operation);
        throw new SecurityException("Unauthorized operation.");
    }

    private void logValidationFailure(String operation) {
        AuthenticatedUser currentSession = session;
        recordSecurityEvent(
                "VALIDATION_FAILURE",
                currentSession == null ? "<anonymous>"
                        : currentSession.username,
                "Rejected input for operation: " + operation);
    }

    public void createNewDatabase() {
        requireRoles("initialize-database", 5);
        initializeDatabase();
    }

    public void createHistoryTable() {
        requireRoles("create-history-table", 5);
        initializeDatabase();
    }

    public void createLogsTable() {
        requireRoles("create-security-logs-table", 5);
        initializeDatabase();
    }

    public void createProductTable() {
        requireRoles("create-products-table", 5);
        initializeDatabase();
    }

    public void createUserTable() {
        requireRoles("create-users-table", 5);
        initializeDatabase();
    }

    public void dropHistoryTable() {
        requireRoles("drop-history-table", 5);
        dropTable("history");
    }

    public void dropLogsTable() {
        requireRoles("drop-security-logs", 5);
        throw new UnsupportedOperationException(
                "Security logs cannot be dropped; use clearLogs instead.");
    }

    public void dropProductTable() {
        requireRoles("drop-products-table", 5);
        dropTable("product");
    }
    
    public void dropUserTable() {
        requireRoles("drop-users-table", 5);
        dropTable("users");
    }

    private void dropTable(String tableName) {
        String[] allowedTables = {"history", "product", "users"};
        if (!Arrays.asList(allowedTables).contains(tableName)) {
            throw new IllegalArgumentException("Invalid table name.");
        }
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (Statement statement = conn.createStatement()) {
                insertLog(conn, "DATABASE_TABLE_DROPPED",
                        session.username,
                        "Administrator dropped table " + tableName,
                        timestamp());
                statement.execute("DROP TABLE IF EXISTS " + tableName);
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw new AppException(
                    "Database table could not be dropped.", false, ex);
        }
    }
    
    @Deprecated
    public void addHistory(
            String username, String name, int quantity, String ignoredTime) {
        AuthenticatedUser currentSession = requireRoles("purchase-product", 2);
        if (!currentSession.username.equals(username)) {
            recordSecurityEvent(
                    "UNAUTHORIZED_OPERATION", currentSession.username,
                    "Denied purchase-history insertion for another account");
            throw new SecurityException("Unauthorized operation.");
        }
        purchaseProduct(name, quantity);
    }

    public void addLogs(
            String event, String username, String description, String time) {
        requireRoles("add-security-log", 5);
        if (event == null || username == null || description == null
                || time == null) {
            logValidationFailure("add-security-log");
            throw new IllegalArgumentException("Log fields are required.");
        }
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                insertLog(conn, event, username, description, time);
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw new AppException("Log entry could not be added.", false, ex);
        }
    }

    public void addProduct(String name, int stock, double price) {
        requireRoles("add-product", 3, 4, 5);
        long cents;
        try {
            cents = priceCents(price);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("add-product");
            throw new IllegalArgumentException(
                    "Price is outside the allowed range.", ex);
        }
        addProduct(name, stock, cents);
    }

    public void addProduct(String name, String stock, String price) {
        requireRoles("add-product", 3, 4, 5);
        int parsedStock;
        long parsedPrice;
        try {
            Validation.productName(name);
            parsedStock = Validation.integer(
                    stock, 0, Validation.MAX_STOCK);
            parsedPrice = Validation.price(price);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("add-product");
            throw ex;
        }
        addProduct(name, parsedStock, parsedPrice);
    }

    public void addProduct(String name, int stock, long priceCents) {
        requireRoles("add-product", 3, 4, 5);
        try {
            Validation.productName(name);
            Validation.integer(
                    String.valueOf(stock), 0, Validation.MAX_STOCK);
            validatePriceCents(priceCents);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("add-product");
            throw ex;
        }

        String sql = "INSERT INTO product(name,stock,price) VALUES(?,?,?)";
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (PreparedStatement statement = conn.prepareStatement(sql)) {
                statement.setString(1, name);
                statement.setInt(2, stock);
                statement.setDouble(3, priceCents / 100.0);
                statement.executeUpdate();
                insertLog(conn, "PRODUCT_CREATED",
                        session.username, "Product created", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "PRODUCT_CREATE_FAILURE", session.username,
                    "Product creation failed");
            throw new AppException(
                    "Product could not be added.", false, ex);
        }
    }

    public void updateProduct(
            String originalName, String name, int stock, long priceCents) {
        requireRoles("edit-product", 3, 4, 5);
        try {
            Validation.productName(originalName);
            Validation.productName(name);
            Validation.integer(
                    String.valueOf(stock), 0, Validation.MAX_STOCK);
            validatePriceCents(priceCents);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("edit-product");
            throw ex;
        }

        String sql = "UPDATE product SET name = ?, stock = ?, price = ? "
                + "WHERE name = ?";
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (PreparedStatement statement = conn.prepareStatement(sql)) {
                statement.setString(1, name);
                statement.setInt(2, stock);
                statement.setDouble(3, priceCents / 100.0);
                statement.setString(4, originalName);
                if (statement.executeUpdate() != 1) {
                    insertLog(conn, "PRODUCT_EDIT_FAILURE",
                            session.username, "Product was not found",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "Product no longer exists.");
                }
                insertLog(conn, "PRODUCT_UPDATED",
                        session.username, "Product updated", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "PRODUCT_EDIT_FAILURE", session.username,
                    "Product update failed");
            throw new AppException(
                    "Product could not be updated.", false, ex);
        }
    }

    public void updateProduct(
            String originalName, String name, String stock, String price) {
        requireRoles("edit-product", 3, 4, 5);
        int parsedStock;
        long parsedPrice;
        try {
            parsedStock = Validation.integer(
                    stock, 0, Validation.MAX_STOCK);
            parsedPrice = Validation.price(price);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("edit-product");
            throw ex;
        }
        updateProduct(originalName, name, parsedStock, parsedPrice);
    }

    public void deleteProduct(String name) {
        requireRoles("delete-product", 3, 4, 5);
        try {
            Validation.productName(name);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("delete-product");
            throw ex;
        }

        try (Connection conn = DriverManager.getConnection(driverURL)) {
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
                    conn.commit();
                    throw new IllegalArgumentException(
                            "Product no longer exists.");
                }

                try (PreparedStatement findHistory = conn.prepareStatement(
                        "SELECT 1 FROM history WHERE product_id = ? "
                        + "OR (product_id IS NULL AND name = ?) LIMIT 1")) {
                    findHistory.setInt(1, productId);
                    findHistory.setString(2, name);
                    try (ResultSet rs = findHistory.executeQuery()) {
                        if (rs.next()) {
                            insertLog(conn, "PRODUCT_DELETE_REJECTED",
                                    session.username,
                                    "Product is referenced by purchase history",
                                    timestamp());
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "Product with purchase history cannot be deleted.");
                        }
                    }
                }

                try (PreparedStatement delete = conn.prepareStatement(
                        "DELETE FROM product WHERE id = ?")) {
                    delete.setInt(1, productId);
                    delete.executeUpdate();
                }
                insertLog(conn, "PRODUCT_DELETED",
                        session.username, "Product deleted", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "PRODUCT_DELETE_FAILURE", session.username,
                    "Product deletion failed");
            throw new AppException(
                    "Product could not be deleted.", false, ex);
        }
    }

    public long purchaseProduct(String productName, int quantity) {
        AuthenticatedUser currentSession = requireRoles(
                "purchase-product", 2);
        try {
            Validation.productName(productName);
            Validation.integer(
                    String.valueOf(quantity), 1, Validation.MAX_STOCK);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("purchase-product");
            throw ex;
        }

        try (Connection conn = DriverManager.getConnection(driverURL)) {
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
                            insertLog(conn, "PURCHASE_REJECTED",
                                    currentSession.username,
                                    "Requested product was not found",
                                    timestamp());
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "Product no longer exists.");
                        }
                        productId = rs.getInt("id");
                        stock = rs.getInt("stock");
                        priceCents = priceCents(rs.getDouble("price"));
                    }
                }

                if (stock < quantity) {
                    insertLog(conn, "PURCHASE_REJECTED",
                            currentSession.username,
                            "Insufficient product stock", timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "There is not enough stock to complete the purchase.");
                }

                long totalCents = Math.multiplyExact(
                        priceCents, (long) quantity);
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE product SET stock = stock - ? "
                        + "WHERE id = ? AND stock >= ?")) {
                    update.setInt(1, quantity);
                    update.setInt(2, productId);
                    update.setInt(3, quantity);
                    if (update.executeUpdate() != 1) {
                        throw new SQLException(
                                "Product stock changed during purchase.");
                    }
                }
                try (PreparedStatement insert = conn.prepareStatement(
                        "INSERT INTO history(username,name,stock,timestamp,"
                        + "user_id,product_id,unit_price_cents) "
                        + "VALUES(?,?,?,?,?,?,?)")) {
                    insert.setString(1, currentSession.username);
                    insert.setString(2, productName);
                    insert.setInt(3, quantity);
                    insert.setString(4, timestamp());
                    insert.setInt(5, currentSession.id);
                    insert.setInt(6, productId);
                    insert.setLong(7, priceCents);
                    insert.executeUpdate();
                }
                insertLog(conn, "PURCHASE_COMPLETED",
                        currentSession.username,
                        "Product purchase completed", timestamp());
                conn.commit();
                return totalCents;
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "PURCHASE_FAILURE", currentSession.username,
                    "Purchase could not be completed");
            throw new AppException(
                    "Purchase could not be completed.", false, ex);
        }
    }

    public long purchaseProduct(String productName, String quantity) {
        requireRoles("purchase-product", 2);
        int parsedQuantity;
        try {
            parsedQuantity = Validation.integer(
                    quantity, 1, Validation.MAX_STOCK);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("purchase-product");
            throw ex;
        }
        return purchaseProduct(productName, parsedQuantity);
    }

    public void addUser(String username, String password) {
        char[] passwordChars = password == null
                ? null : password.toCharArray();
        try {
            addUser(username, passwordChars, passwordChars);
        } finally {
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0');
            }
        }
    }

    public void addUser(
            String username, char[] password, char[] confirmation) {
        createUser(username, password, confirmation, 2, false);
    }

    public void addUser(String username, String password, int role) {
        requireRoles("add-user", 5);
        char[] passwordChars = password == null
                ? null : password.toCharArray();
        try {
            createUser(username, passwordChars, passwordChars, role, true);
        } finally {
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0');
            }
        }
    }

    public void addUser(
            String username, char[] password,
            char[] confirmation, int role) {
        requireRoles("add-user", 5);
        createUser(username, password, confirmation, role, true);
    }

    private void createUser(
            String username,
            char[] password,
            char[] confirmation,
            int role,
            boolean administratorCreated) {

        try {
            Validation.username(username);
            Validation.password(password, confirmation);
            Validation.role(role);
        } catch (IllegalArgumentException ex) {
            logValidationFailure(
                    administratorCreated ? "add-user" : "register");
            throw ex;
        }

        String sql = "INSERT INTO users(username,password,role) "
                + "VALUES(?,?,?)";
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (PreparedStatement statement = conn.prepareStatement(sql)) {
                statement.setString(1, username);
                statement.setString(2, PasswordHasher.hash(password));
                statement.setInt(3, role);
                statement.executeUpdate();
                insertLog(conn,
                        administratorCreated
                                ? "USER_CREATED_BY_ADMIN" : "USER_REGISTERED",
                        administratorCreated ? session.username : username,
                        administratorCreated
                                ? "Administrator created an account"
                                : "New account registered",
                        timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    administratorCreated
                            ? "USER_CREATION_FAILURE"
                            : "USER_REGISTRATION_FAILURE",
                    administratorCreated ? session.username : username,
                    "Account creation failed");
            throw new AppException(
                    administratorCreated
                            ? "User creation could not be completed."
                            : "Registration could not be completed.",
                    false, ex);
        }
    }

    public ArrayList<History> getHistory() {
        AuthenticatedUser currentSession = requireRoles(
                "view-history", 2, 4, 5);
        boolean ownHistoryOnly = currentSession.role == 2;
        String sql = "SELECT id, user_id, product_id, username, name, "
                + "stock, unit_price_cents, timestamp FROM history"
                + (ownHistoryOnly
                        ? " WHERE user_id = ? OR (user_id IS NULL AND username = ?)"
                        : "")
                + " ORDER BY timestamp DESC, id DESC";
        ArrayList<History> histories = new ArrayList<History>();
        try (Connection conn = DriverManager.getConnection(driverURL);
                PreparedStatement statement = conn.prepareStatement(sql)) {
            if (ownHistoryOnly) {
                statement.setInt(1, currentSession.id);
                statement.setString(2, currentSession.username);
            }
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    int userId = rs.getInt("user_id");
                    Integer historyUserId = rs.wasNull()
                            ? null : Integer.valueOf(userId);
                    int productId = rs.getInt("product_id");
                    Integer historyProductId = rs.wasNull()
                            ? null : Integer.valueOf(productId);
                    long unitPriceCents = rs.getLong("unit_price_cents");
                    Long historyPrice = rs.wasNull()
                            ? null : Long.valueOf(unitPriceCents);
                    histories.add(new History(
                            rs.getInt("id"),
                            historyUserId == null ? 0 : historyUserId,
                            historyProductId == null
                                    ? 0 : historyProductId,
                            rs.getString("username"),
                            rs.getString("name"),
                            rs.getInt("stock"),
                            historyPrice,
                            rs.getString("timestamp")));
                }
            }
            return histories;
        } catch (SQLException ex) {
            throw new AppException(
                    "Purchase history could not be loaded.", false, ex);
        }
    }

    public ArrayList<History> searchHistory(String query) {
        requireRoles("search-history", 2, 4, 5);
        try {
            Validation.search(query);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("search-history");
            throw ex;
        }

        ArrayList<History> matches = new ArrayList<History>();
        for (History entry : getHistory()) {
            if (entry.getUsername().equalsIgnoreCase(query)
                    || query.contains(entry.getName())
                    || entry.getName().contains(query)) {
                matches.add(entry);
            }
        }
        return matches;
    }

    public ArrayList<Logs> getLogs() {
        requireRoles("view-security-logs", 5);
        ArrayList<Logs> logs = new ArrayList<Logs>();
        String sql = "SELECT id, event, username, desc, timestamp "
                + "FROM logs ORDER BY timestamp DESC, id DESC";
        try (Connection conn = DriverManager.getConnection(driverURL);
                Statement statement = conn.createStatement();
                ResultSet rs = statement.executeQuery(sql)) {
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
            throw new AppException(
                    "Security logs could not be loaded.", false, ex);
        }
    }

    public void clearLogs() {
        AuthenticatedUser currentSession = requireRoles(
                "clear-security-logs", 5);
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try (Statement statement = conn.createStatement()) {
                statement.executeUpdate("DELETE FROM logs");
                insertLog(conn, "SECURITY_LOGS_CLEARED",
                        currentSession.username,
                        "Administrator cleared security logs", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            throw new AppException(
                    "Security logs could not be cleared.", false, ex);
        }
    }

    public ArrayList<Product> getProduct() {
        requireRoles("view-products", 2, 3, 4, 5);
        ArrayList<Product> products = new ArrayList<Product>();
        String sql = "SELECT id, name, stock, price FROM product "
                + "ORDER BY id";
        try (Connection conn = DriverManager.getConnection(driverURL);
                Statement statement = conn.createStatement();
                ResultSet rs = statement.executeQuery(sql)) {
            while (rs.next()) {
                products.add(mapProduct(rs));
            }
            return products;
        } catch (SQLException ex) {
            throw new AppException(
                    "Products could not be loaded.", false, ex);
        }
    }

    public ArrayList<User> getUsers() {
        requireRoles("view-users", 5);
        ArrayList<User> users = new ArrayList<User>();
        String sql = "SELECT id, username, role, locked, failed_attempts "
                + "FROM users ORDER BY id";
        try (Connection conn = DriverManager.getConnection(driverURL);
                Statement statement = conn.createStatement();
                ResultSet rs = statement.executeQuery(sql)) {
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
            throw new AppException(
                    "Users could not be loaded.", false, ex);
        }
    }

    public void updateUserRole(String username, int role) {
        AuthenticatedUser currentSession = requireRoles(
                "edit-user-role", 5);
        validateUserName(username, "edit-user-role");
        try {
            Validation.role(role);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("edit-user-role");
            throw ex;
        }

        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                int targetId;
                int oldRole;
                Integer oldRoleBeforeLock;
                int oldLocked;
                try (PreparedStatement find = conn.prepareStatement(
                        "SELECT id, role, locked, role_before_lock "
                        + "FROM users WHERE username = ?")) {
                    find.setString(1, username);
                    try (ResultSet rs = find.executeQuery()) {
                        if (!rs.next()) {
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "User no longer exists.");
                        }
                        targetId = rs.getInt("id");
                        oldRole = rs.getInt("role");
                        oldLocked = rs.getInt("locked");
                        oldRoleBeforeLock =
                                getNullableInt(rs, "role_before_lock");
                    }
                }
                if (targetId == currentSession.id && role != 5) {
                    insertLog(conn, "USER_ROLE_CHANGE_REJECTED",
                            currentSession.username,
                            "Administrator cannot demote their own account",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "You cannot remove your own administrator role.");
                }
                if (oldRole == 5 && role != 5
                        && countAdministrators(conn) <= 1) {
                    insertLog(conn, "USER_ROLE_CHANGE_REJECTED",
                            currentSession.username,
                            "Cannot remove the last administrator",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "At least one administrator must remain.");
                }
                Integer roleBeforeLock = role == 1
                        ? (oldLocked == 0 && oldRole >= 2 && oldRole <= 5
                                ? Integer.valueOf(oldRole)
                                : oldRoleBeforeLock)
                        : null;
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE users SET role = ?, locked = ?, "
                        + "role_before_lock = ?, failed_attempts = 0 "
                        + "WHERE id = ?")) {
                    update.setInt(1, role);
                    update.setInt(2, role == 1 ? 1 : 0);
                    if (roleBeforeLock == null) {
                        update.setNull(3, java.sql.Types.INTEGER);
                    } else {
                        update.setInt(3, roleBeforeLock.intValue());
                    }
                    update.setInt(4, targetId);
                    update.executeUpdate();
                }
                insertLog(conn, "USER_ROLE_CHANGED",
                        currentSession.username,
                        "Account role changed", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "USER_ROLE_CHANGE_FAILURE", currentSession.username,
                    "Account role change failed");
            throw new AppException(
                    "User role could not be changed.", false, ex);
        }
    }

    public void setUserLocked(String username, boolean locked) {
        AuthenticatedUser currentSession = requireRoles(
                locked ? "lock-user" : "unlock-user", 5);
        validateUserName(username, locked ? "lock-user" : "unlock-user");
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                int targetId;
                int role;
                int isLocked;
                Integer roleBeforeLock;
                try (PreparedStatement find = conn.prepareStatement(
                        "SELECT id, role, locked, role_before_lock "
                        + "FROM users WHERE username = ?")) {
                    find.setString(1, username);
                    try (ResultSet rs = find.executeQuery()) {
                        if (!rs.next()) {
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "User no longer exists.");
                        }
                        targetId = rs.getInt("id");
                        role = rs.getInt("role");
                        isLocked = rs.getInt("locked");
                        roleBeforeLock =
                                getNullableInt(rs, "role_before_lock");
                    }
                }
                if (targetId == currentSession.id) {
                    insertLog(conn, "ACCOUNT_LOCK_CHANGE_REJECTED",
                            currentSession.username,
                            "Administrator cannot lock their own account",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "You cannot lock or unlock your own account.");
                }
                if (locked && role == 5
                        && countActiveAdministrators(conn) <= 1) {
                    insertLog(conn, "ACCOUNT_LOCK_CHANGE_REJECTED",
                            currentSession.username,
                            "Cannot lock the last active administrator",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "At least one active administrator must remain.");
                }
                if ((locked ? 1 : 0) == isLocked) {
                    conn.commit();
                    return;
                }
                if (!locked && roleBeforeLock == null) {
                    conn.commit();
                    throw new IllegalArgumentException(
                            "The original role is not recorded. "
                            + "Use Edit Role to choose the account's "
                            + "intended role before unlocking it.");
                }
                int resultingRole = locked ? 1 : roleBeforeLock.intValue();
                Integer resultingRoleBeforeLock =
                        locked && role >= 2 && role <= 5
                                ? Integer.valueOf(role) : null;
                try (PreparedStatement update = conn.prepareStatement(
                        "UPDATE users SET locked = ?, role = ?, "
                        + "role_before_lock = ?, failed_attempts = 0 "
                        + "WHERE id = ?")) {
                    update.setInt(1, locked ? 1 : 0);
                    update.setInt(2, resultingRole);
                    if (resultingRoleBeforeLock == null) {
                        update.setNull(3, java.sql.Types.INTEGER);
                    } else {
                        update.setInt(3, resultingRoleBeforeLock.intValue());
                    }
                    update.setInt(4, targetId);
                    update.executeUpdate();
                }
                insertLog(conn,
                        locked ? "ACCOUNT_LOCKED" : "ACCOUNT_UNLOCKED",
                        currentSession.username,
                        "Administrator changed account lock status",
                        timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    locked ? "ACCOUNT_LOCK_FAILURE"
                            : "ACCOUNT_UNLOCK_FAILURE",
                    currentSession.username,
                    "Account lock status could not be changed");
            throw new AppException(
                    "Account lock status could not be changed.", false, ex);
        }
    }

    public void changeUserPassword(
            String username, char[] currentPassword,
            char[] password, char[] confirmation) {
        AuthenticatedUser currentSession = requireRoles(
                "change-user-password", 5);
        validateUserName(username, "change-user-password");
        try {
            Validation.password(password, confirmation);
        } catch (IllegalArgumentException ex) {
            logValidationFailure("change-user-password");
            throw ex;
        }
        String storedAdministratorPassword;
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                try (PreparedStatement statement = conn.prepareStatement(
                        "SELECT password, role, locked FROM users "
                        + "WHERE id = ? AND username = ?")) {
                    statement.setInt(1, currentSession.id);
                    statement.setString(2, currentSession.username);
                    try (ResultSet rs = statement.executeQuery()) {
                        if (!rs.next()
                                || rs.getInt("role") != 5
                                || rs.getInt("locked") != 0) {
                            conn.rollback();
                            invalidateSession();
                            recordSecurityEvent(
                                    "REAUTHORIZATION_FAILURE",
                                    currentSession.username,
                                    "Password change denied because "
                                    + "administrator authorization changed");
                            throw new SecurityException(
                                    "Administrator authorization is no "
                                    + "longer valid.");
                        }
                        storedAdministratorPassword =
                                rs.getString("password");
                    }
                }

                if (!matchesPassword(
                        currentPassword, storedAdministratorPassword)) {
                    insertLog(conn, "REAUTHENTICATION_FAILURE",
                            currentSession.username,
                            "Password change re-authentication failed",
                            timestamp());
                    conn.commit();
                    throw new SecurityException(
                            "The current password is incorrect.");
                }

                try (PreparedStatement statement = conn.prepareStatement(
                        "UPDATE users SET password = ?, failed_attempts = 0 "
                        + "WHERE username = ?")) {
                    statement.setString(1, PasswordHasher.hash(password));
                    statement.setString(2, username);
                    if (statement.executeUpdate() != 1) {
                        conn.commit();
                        throw new IllegalArgumentException(
                                "User no longer exists.");
                    }
                    insertLog(conn, "USER_PASSWORD_CHANGED",
                            currentSession.username,
                            "Administrator changed an account password",
                            timestamp());
                    conn.commit();
                }
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "USER_PASSWORD_CHANGE_FAILURE",
                    currentSession.username,
                    "Account password change failed");
            throw new AppException(
                    "Password could not be changed.", false, ex);
        }
    }

    private static boolean matchesPassword(
            char[] password, String storedPassword) {
        if (password == null || storedPassword == null) {
            return false;
        }
        if (PasswordHasher.isHash(storedPassword)) {
            return PasswordHasher.verify(password, storedPassword);
        }
        return !storedPassword.startsWith("pbkdf2-sha256$")
                && matchesLegacyPassword(password, storedPassword);
    }

    private static Integer getNullableInt(
            ResultSet rs, String column) throws SQLException {
        int value = rs.getInt(column);
        return rs.wasNull() ? null : Integer.valueOf(value);
    }

    public void deleteUser(String username) {
        AuthenticatedUser currentSession = requireRoles(
                "delete-user", 5);
        validateUserName(username, "delete-user");
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            conn.setAutoCommit(false);
            try {
                int targetId;
                int role;
                try (PreparedStatement find = conn.prepareStatement(
                        "SELECT id, role FROM users WHERE username = ?")) {
                    find.setString(1, username);
                    try (ResultSet rs = find.executeQuery()) {
                        if (!rs.next()) {
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "User no longer exists.");
                        }
                        targetId = rs.getInt("id");
                        role = rs.getInt("role");
                    }
                }
                if (targetId == currentSession.id) {
                    insertLog(conn, "USER_DELETE_REJECTED",
                            currentSession.username,
                            "Administrator cannot delete their own account",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "You cannot delete your own account.");
                }
                if (role == 5 && countAdministrators(conn) <= 1) {
                    insertLog(conn, "USER_DELETE_REJECTED",
                            currentSession.username,
                            "Cannot delete the last administrator",
                            timestamp());
                    conn.commit();
                    throw new IllegalArgumentException(
                            "At least one administrator must remain.");
                }
                try (PreparedStatement findHistory = conn.prepareStatement(
                        "SELECT 1 FROM history WHERE user_id = ? "
                        + "OR (user_id IS NULL AND username = ?) LIMIT 1")) {
                    findHistory.setInt(1, targetId);
                    findHistory.setString(2, username);
                    try (ResultSet rs = findHistory.executeQuery()) {
                        if (rs.next()) {
                            insertLog(conn, "USER_DELETE_REJECTED",
                                    currentSession.username,
                                    "Account is referenced by purchase history",
                                    timestamp());
                            conn.commit();
                            throw new IllegalArgumentException(
                                    "User with purchase history cannot be deleted.");
                        }
                    }
                }
                try (PreparedStatement delete = conn.prepareStatement(
                        "DELETE FROM users WHERE id = ?")) {
                    delete.setInt(1, targetId);
                    delete.executeUpdate();
                }
                insertLog(conn, "USER_DELETED",
                        currentSession.username,
                        "Administrator deleted an account", timestamp());
                conn.commit();
            } catch (SQLException ex) {
                rollback(conn, ex);
                throw ex;
            }
        } catch (SQLException ex) {
            recordSecurityEvent(
                    "USER_DELETE_FAILURE", currentSession.username,
                    "Account deletion failed");
            throw new AppException(
                    "User could not be deleted.", false, ex);
        }
    }

    public void removeUser(String username) {
        deleteUser(username);
    }

    public Product getProduct(String name) {
        requireRoles("view-product", 2, 3, 4, 5);
        String sql = "SELECT id, name, stock, price FROM product WHERE name = ?";
        try (Connection conn = DriverManager.getConnection(driverURL);
                PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.setString(1, name);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() ? mapProduct(rs) : null;
            }
        } catch (SQLException ex) {
            throw new AppException(
                    "Product could not be loaded.", false, ex);
        }
    }

    private static Product mapProduct(ResultSet rs) throws SQLException {
        return new Product(
                rs.getInt("id"),
                rs.getString("name"),
                rs.getInt("stock"),
                priceCents(rs.getDouble("price")));
    }

    private static void validatePriceCents(long priceCents) {
        if (priceCents < 0 || priceCents > Validation.MAX_PRICE_CENTS) {
            throw new IllegalArgumentException(
                    "Price is outside the allowed range.");
        }
    }

    private void validateUserName(String username, String operation) {
        try {
            Validation.username(username);
        } catch (IllegalArgumentException ex) {
            logValidationFailure(operation);
            throw ex;
        }

    }

    private static int countAdministrators(Connection conn)
            throws SQLException {
        try (Statement statement = conn.createStatement();
                ResultSet rs = statement.executeQuery(
                        "SELECT COUNT(*) FROM users WHERE role = 5")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    private static int countActiveAdministrators(Connection conn)
            throws SQLException {
        try (Statement statement = conn.createStatement();
                ResultSet rs = statement.executeQuery(
                        "SELECT COUNT(*) FROM users "
                        + "WHERE role = 5 AND locked = 0")) {
            return rs.next() ? rs.getInt(1) : 0;
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