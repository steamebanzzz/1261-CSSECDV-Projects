package Controller;

import Model.History;
import Model.LoginResult;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Headless verification of the demo checklist (sections 2.1-2.5) against the
 * controller. Run it ONLY from a disposable copy of database.db placed in a
 * directory under the system temp folder whose name starts with
 * "security-checklist-" (it creates users, products and logs).
 *
 *   java -cp build/classes;build/test/classes;lib/sqlite-jdbc-3.23.1.jar \
 *        Controller.SecurityChecklistTest
 */
public final class SecurityChecklistTest {

    private static final String PASSWORD = "Checklist#Pass42";
    private static int passed;
    private static int failed;

    private SecurityChecklistTest() {
    }

    public static void main(String[] args) throws Exception {
        guardDisposableDatabase();
        SQLite sqlite = new SQLite();
        String suffix = Long.toString(System.nanoTime() % 100000);
        String client = "tclient" + suffix;
        String client2 = "tclienttwo" + suffix;
        String staff = "tstaff" + suffix;
        String manager = "tmanager" + suffix;
        String admin = "tadmin" + suffix;
        String admin2 = "tadmintwo" + suffix;
        createUser(client, 2);
        createUser(client2, 2);
        createUser(staff, 3);
        createUser(manager, 4);
        createUser(admin, 5);
        createUser(admin2, 5);
        String product = "Widget" + suffix;
        createProduct(product, 1000, 1.00);

        // ---------------------------------------------------------- 2.1
        section("2.1 Authentication");
        check("2.1.3 no plaintext password remains after startup migration",
                countNonHashedPasswords() == 0);
        check("2.1.3 hashes are salted PBKDF2 (same password, different hash)",
                differentHashesForSamePassword());

        check("2.1.4 unknown user and wrong password give the same result",
                !sqlite.login("nosuchuser" + suffix, chars(PASSWORD))
                        .isSuccessful()
                && !sqlite.login(client, chars("Wrong#Pass4242"))
                        .isSuccessful());
        long unknown = time(() -> sqlite.login("nosuch" + suffix,
                chars("Wrong#Pass4242")));
        long existing = time(() -> sqlite.login(client2,
                chars("Wrong#Pass4242")));
        double ratio = (double) Math.max(unknown, existing)
                / Math.max(1, Math.min(unknown, existing));
        check("2.1.4 login timing does not reveal valid usernames (ratio "
                + String.format("%.2f", ratio) + ")", ratio < 2.0);
        resetFailures(client);
        resetFailures(client2);

        check("2.1.5 weak passwords rejected at registration",
                rejected(() -> sqlite.addUser("weak1" + suffix,
                        chars("alllowercase1!"), chars("alllowercase1!")))
                && rejected(() -> sqlite.addUser("weak2" + suffix,
                        chars("NoSymbols12345"), chars("NoSymbols12345")))
                && rejected(() -> sqlite.addUser("weak3" + suffix,
                        chars("NoDigits!!Abcd"), chars("NoDigits!!Abcd"))));
        check("2.1.6 minimum (12) and maximum (128) length enforced",
                rejected(() -> sqlite.addUser("short" + suffix,
                        chars("Ab1!Ab1!Ab1"), chars("Ab1!Ab1!Ab1")))
                && rejected(() -> sqlite.addUser("long" + suffix,
                        chars(repeat("Ab1!", 33)), chars(repeat("Ab1!", 33)))));
        sqlite.addUser("newreg" + suffix, chars(PASSWORD), chars(PASSWORD));
        check("2.1.5 valid registration creates a hashed Client (role 2)",
                roleOf("newreg" + suffix) == 2
                && PasswordHasher.isHash(passwordOf("newreg" + suffix)));
        check("usernames are case-insensitive (duplicate rejected)",
                failsWith(() -> sqlite.addUser(
                        "NEWREG" + suffix, chars(PASSWORD), chars(PASSWORD)),
                        AppException.class));

        String lockMe = "lockme" + suffix;
        createUser(lockMe, 2);
        for (int i = 0; i < 4; i++) {
            sqlite.login(lockMe, chars("Wrong#Pass4242"));
        }
        check("2.1.8 not locked after four failures", roleOf(lockMe) == 2);
        sqlite.login(lockMe, chars("Wrong#Pass4242"));
        check("2.1.8 locked to role 1 after exactly five failures",
                roleOf(lockMe) == 1 && lockedOf(lockMe) == 1
                && logged("ACCOUNT_LOCKED", lockMe));
        check("2.1.8 locked account rejected even with correct password",
                !sqlite.login(lockMe, chars(PASSWORD)).isSuccessful());

        String lengthLock = "lenlock" + suffix;
        createUser(lengthLock, 2);
        sqlite.login(lengthLock, chars(""));
        check("2.1.8 / 2.1.9 blank password counts and records the attempt",
                failuresOf(lengthLock) == 1
                && "FAILURE".equals(statusOf(lengthLock))
                && logged("LOGIN_VALIDATION_FAILURE", lengthLock));
        sqlite.login(lengthLock, chars(repeat("A", 129)));
        sqlite.login(lengthLock, chars(""));
        sqlite.login(lengthLock, chars(repeat("A", 129)));
        check("2.1.8 four blank/over-long attempts do not lock yet",
                roleOf(lengthLock) == 2 && failuresOf(lengthLock) == 4);
        sqlite.login(lengthLock, chars(""));
        check("2.1.8 fifth consecutive blank/over-long attempt locks (role 1)",
                roleOf(lengthLock) == 1 && lockedOf(lengthLock) == 1
                && logged("ACCOUNT_LOCKED", lengthLock));

        String lastSeen = "lastseen" + suffix;
        createUser(lastSeen, 2);
        sqlite.login(lastSeen, chars(repeat("B", 129)));
        LoginResult afterLong = sqlite.login(lastSeen, chars(PASSWORD));
        check("2.1.9 over-long attempt is reported at the next login",
                afterLong.isSuccessful()
                && "FAILURE".equals(afterLong.getPreviousStatus())
                && afterLong.getFailedAttemptsSinceLastLogin() == 1);
        sqlite.logout();

        for (int i = 0; i < 3; i++) {
            sqlite.login(client, chars("Wrong#Pass4242"));
        }
        LoginResult ok = sqlite.login(client, chars(PASSWORD));
        check("2.1.9 last attempt time/status and failure count reported",
                ok.isSuccessful() && ok.getPreviousTime() != null
                && "FAILURE".equals(ok.getPreviousStatus())
                && ok.getFailedAttemptsSinceLastLogin() == 3);
        sqlite.logout();

        sqlite.login(admin, chars(PASSWORD));
        check("2.1.10 password change refused with wrong current password",
                rejected(() -> sqlite.changeUserPassword(client,
                        chars("Wrong#Pass4242"), chars("Brand#NewPass9"),
                        chars("Brand#NewPass9"))));
        sqlite.changeUserPassword(client, chars(PASSWORD),
                chars(PASSWORD), chars(PASSWORD));
        check("2.1.10 password change succeeds after re-authentication",
                logged("REAUTHENTICATION_SUCCESS", admin));
        for (int i = 0; i < 5; i++) {
            try {
                sqlite.changeUserPassword(client, chars("Wrong#Pass4242"),
                        chars(PASSWORD), chars(PASSWORD));
            } catch (RuntimeException expected) {
                // counted
            }
        }
        check("2.1.10 five failed re-authentications lock and sign out",
                sqlite.getAuthenticatedRole() == 0 && roleOf(admin) == 1);
        superAdminUnlock(admin, 5);

        check("2.1.1 / 2.1.2 every operation denied without a session",
                denied(sqlite::getProduct) && denied(sqlite::getUsers)
                && denied(sqlite::getLogs) && denied(sqlite::getHistory));
        check("2.3.3 login rejects a 129-character password (logged)",
                !sqlite.login(client, chars(repeat("A", 129)))
                        .isSuccessful()
                && logged("LOGIN_VALIDATION_FAILURE", client));

        // ---------------------------------------------------------- 2.2
        section("2.2 Authorization (matrix from the role descriptions)");
        String[] operations = {"view products", "purchase", "add product",
            "edit product", "delete product", "view history", "view users",
            "add user", "view logs", "archive logs"};
        Map<String, boolean[]> expected = new LinkedHashMap<>();
        expected.put(client, new boolean[]{
            true, true, false, false, false, true, false, false, false,
            false});
        expected.put(staff, new boolean[]{
            true, false, true, true, true, false, false, false, false,
            false});
        expected.put(manager, new boolean[]{
            true, false, true, true, true, true, false, false, false,
            false});
        expected.put(admin, new boolean[]{
            false, false, false, false, false, false, true, true, true,
            true});
        for (Map.Entry<String, boolean[]> entry : expected.entrySet()) {
            sqlite.login(entry.getKey(), chars(PASSWORD));
            String temp = "Tmp" + entry.getKey();
            createProduct(temp, 5, 1.0);
            Runnable[] ops = {
                sqlite::getProduct,
                () -> sqlite.purchaseProduct(product, "1"),
                () -> sqlite.addProduct("New" + entry.getKey(), "1", "1.00"),
                () -> sqlite.updateProduct(temp, temp, "6", "2.00"),
                () -> sqlite.deleteProduct(temp),
                sqlite::getHistory,
                sqlite::getUsers,
                () -> sqlite.addUser("made" + entry.getKey(),
                        chars(PASSWORD), chars(PASSWORD), 3),
                sqlite::getLogs,
                sqlite::archiveLogs
            };
            for (int i = 0; i < ops.length; i++) {
                boolean allowed = !denied(ops[i]);
                check("2.2.2 role " + roleOf(entry.getKey()) + " "
                        + operations[i] + " -> "
                        + (allowed ? "allowed" : "denied"),
                        allowed == entry.getValue()[i]);
            }
            sqlite.logout();
        }

        sqlite.login(client, chars(PASSWORD));
        sqlite.purchaseProduct(product, "2");
        ArrayList<History> own = sqlite.getHistory();
        boolean onlyOwn = !own.isEmpty();
        for (History history : own) {
            onlyOwn &= history.getUsername().equalsIgnoreCase(client);
        }
        check("2.2.2 client sees only their own purchase history", onlyOwn);
        sqlite.logout();

        sqlite.login(admin, chars(PASSWORD));
        check("2.2.2 admin cannot grant the Admin role",
                denied(() -> sqlite.updateUserRole(client, 5,
                        chars(PASSWORD))));
        check("2.2.2 admin cannot create an Admin account",
                denied(() -> sqlite.addUser("evil" + suffix, chars(PASSWORD),
                        chars(PASSWORD), 5)));
        check("2.2.2 admin cannot modify another admin account",
                denied(() -> sqlite.setUserLocked(admin2, true))
                && denied(() -> sqlite.deleteUser(admin2, chars(PASSWORD))));
        sqlite.updateUserRole(staff, 4, chars(PASSWORD));
        check("admin can change a staff role after re-authentication",
                roleOf(staff) == 4);
        setRole(staff, 3);
        sqlite.logout();

        sqlite.login(manager, chars(PASSWORD));
        setRole(manager, 2); // demoted by another session / the admin
        check("2.2.3 / 2.2.4 demoted user is blocked from the Manager panel",
                !sqlite.authorizeView(
                        AccessControl.Permission.VIEW_MANAGER_HOME,
                        "Manager Home")
                && sqlite.getAuthenticatedRole() == 2);
        check("2.5.4 panel access violation logged",
                logged("ACCESS_VIOLATION", manager));
        setRole(manager, 1);
        setLocked(manager, 1);
        check("2.2.3 disabled account loses its session on next request",
                denied(sqlite::getProduct)
                && sqlite.getAuthenticatedRole() == 0
                && logged("SESSION_REVOKED", manager));
        setLocked(manager, 0);
        setRole(manager, 4);

        // ---------------------------------------------------------- 2.3
        section("2.3 Data validation");
        sqlite.login(staff, chars(PASSWORD));
        check("2.3.1 suspicious input rejected, not cleaned",
                rejected(() -> sqlite.addProduct("Bad'; DROP TABLE users;--",
                        "1", "1.00"))
                && rejected(() -> sqlite.addProduct("<script>x</script>",
                        "1", "1.00"))
                && !productExists("BadDROPTABLEusers"));
        check("2.3.2 numeric ranges enforced",
                rejected(() -> sqlite.addProduct("Rng" + suffix, "-1",
                        "1.00"))
                && rejected(() -> sqlite.addProduct("Rng" + suffix,
                        "1000001", "1.00"))
                && rejected(() -> sqlite.addProduct("Rng" + suffix, "1",
                        "0"))
                && rejected(() -> sqlite.addProduct("Rng" + suffix, "1",
                        "1.001")));
        check("2.3.3 maximum lengths enforced (product name)",
                rejected(() -> sqlite.addProduct(repeat("A", 65), "1",
                        "1.00")));
        check("2.5.2 validation failures logged with timestamp",
                logged("VALIDATION_FAILURE", staff));
        String dupe = "Dupe" + suffix;
        createProduct(dupe, 1, 1.0);
        check("2.5.2 duplicate product name rejected and logged",
                rejected(() -> sqlite.addProduct(dupe, "1", "1.00"))
                && loggedDesc("VALIDATION_FAILURE", staff,
                        "add-product (A product with that name"));
        check("2.5.2 editing a missing product rejected and logged",
                rejected(() -> sqlite.updateProduct("Gone" + suffix,
                        "Gone" + suffix, "1", "1.00"))
                && loggedDesc("VALIDATION_FAILURE", staff,
                        "edit-product (Product no longer exists"));
        check("2.5.2 deleting a missing product rejected and logged",
                rejected(() -> sqlite.deleteProduct("Gone" + suffix))
                && loggedDesc("VALIDATION_FAILURE", staff,
                        "delete-product (Product no longer exists"));
        sqlite.logout();
        sqlite.login(admin, chars(PASSWORD));
        check("2.5.2 duplicate username (admin add) rejected and logged",
                rejected(() -> sqlite.addUser(client, chars(PASSWORD),
                        chars(PASSWORD), 2))
                && loggedDesc("VALIDATION_FAILURE", admin,
                        "add-user (That username is already taken"));
        sqlite.logout();
        sqlite.login(manager, chars(PASSWORD));
        check("2.3.3 maximum lengths enforced (search, 64 max)",
                rejected(() -> sqlite.searchHistory(repeat("A", 65)))
                && sqlite.searchHistory(repeat("A", 64)) != null);
        sqlite.logout();
        int usersBefore = countUsers();
        check("2.3.4 SQL injection in login is rejected",
                !sqlite.login("admin' OR '1'='1", chars("x' OR '1'='1"))
                        .isSuccessful()
                && countUsers() == usersBefore);

        // ---------------------------------------------------------- 2.4
        section("2.4 Error handling");
        setPlaintextPassword(client2, PASSWORD);
        check("2.4 / 2.1.2 non-hashed stored password fails closed",
                !sqlite.login(client2, chars(PASSWORD)).isSuccessful()
                && logged("CREDENTIAL_INTEGRITY_FAILURE", client2));
        check("2.4.2 denial message is generic",
                messageOf(sqlite::getLogs).equals(
                        "You are not authorized to perform this action."));

        // ---------------------------------------------------------- 2.5
        section("2.5 Logging");
        check("2.5.3 successful and failed logins logged",
                logged("LOGIN_SUCCESS", client)
                && logged("LOGIN_FAILURE", client));
        check("2.5.4 unauthorized operations logged",
                logged("UNAUTHORIZED_OPERATION", client));
        sqlite.login(admin, chars(PASSWORD));
        int totalBefore = countLogs();
        sqlite.archiveLogs();
        check("2.5.1 archive hides entries but deletes nothing",
                sqlite.getLogs().size() == 1 && countLogs() == totalBefore + 1);
        sqlite.logout();

        System.out.println();
        System.out.println("RESULT: " + passed + " passed, " + failed
                + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------ helpers

    private static void guardDisposableDatabase() throws Exception {
        Path temp = Paths.get(System.getProperty("java.io.tmpdir"))
                .toRealPath();
        Path db = new File("database.db").getCanonicalFile().toPath();
        if (!db.startsWith(temp) || !db.getParent().getFileName().toString()
                .startsWith("security-checklist-")) {
            throw new IllegalStateException("Run only against a disposable "
                    + "database copy in a temp 'security-checklist-*' dir.");
        }
    }

    private static Connection db() throws Exception {
        return DriverManager.getConnection("jdbc:sqlite:database.db");
    }

    private static void createUser(String name, int role) throws Exception {
        try (Connection c = db(); PreparedStatement s = c.prepareStatement(
                "INSERT INTO users(username,password,role,locked,"
                + "failed_attempts) VALUES(?,?,?,0,0)")) {
            s.setString(1, name);
            s.setString(2, PasswordHasher.hash(chars(PASSWORD)));
            s.setInt(3, role);
            s.executeUpdate();
        }
    }

    private static void createProduct(String name, int stock, double price)
            throws Exception {
        try (Connection c = db(); PreparedStatement s = c.prepareStatement(
                "INSERT OR IGNORE INTO product(name,stock,price) "
                + "VALUES(?,?,?)")) {
            s.setString(1, name);
            s.setInt(2, stock);
            s.setDouble(3, price);
            s.executeUpdate();
        }
    }

    private static void update(String sql, Object... values) {
        try (Connection c = db(); PreparedStatement s = c.prepareStatement(sql)) {
            for (int i = 0; i < values.length; i++) {
                s.setObject(i + 1, values[i]);
            }
            s.executeUpdate();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void setRole(String name, int role) {
        update("UPDATE users SET role = ? WHERE username = ?", role, name);
    }

    private static void setLocked(String name, int locked) {
        update("UPDATE users SET locked = ? WHERE username = ?", locked, name);
    }

    private static void resetFailures(String name) {
        update("UPDATE users SET failed_attempts = 0 WHERE username = ?",
                name);
    }

    private static void superAdminUnlock(String name, int role) {
        update("UPDATE users SET role = ?, locked = 0, failed_attempts = 0 "
                + "WHERE username = ?", role, name);
    }

    private static void setPlaintextPassword(String name, String password) {
        update("UPDATE users SET password = ? WHERE username = ?", password,
                name);
    }

    private static Object single(String sql, Object... values) {
        try (Connection c = db(); PreparedStatement s = c.prepareStatement(sql)) {
            for (int i = 0; i < values.length; i++) {
                s.setObject(i + 1, values[i]);
            }
            try (ResultSet rs = s.executeQuery()) {
                return rs.next() ? rs.getObject(1) : null;
            }
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static int roleOf(String name) {
        return ((Number) single("SELECT role FROM users WHERE username = ?",
                name)).intValue();
    }

    private static int lockedOf(String name) {
        return ((Number) single("SELECT locked FROM users WHERE username = ?",
                name)).intValue();
    }

    private static String passwordOf(String name) {
        return (String) single("SELECT password FROM users WHERE username = ?",
                name);
    }

    private static int countUsers() {
        return ((Number) single("SELECT COUNT(*) FROM users")).intValue();
    }

    private static int countLogs() {
        return ((Number) single("SELECT COUNT(*) FROM logs")).intValue();
    }

    private static boolean productExists(String name) {
        return single("SELECT 1 FROM product WHERE name = ?", name) != null;
    }

    private static int countNonHashedPasswords() throws Exception {
        int count = 0;
        try (Connection c = db(); PreparedStatement s = c.prepareStatement(
                "SELECT password FROM users"); ResultSet rs = s.executeQuery()) {
            while (rs.next()) {
                if (!PasswordHasher.isHash(rs.getString(1))) {
                    count++;
                }
            }
        }
        return count;
    }

    private static boolean differentHashesForSamePassword() {
        String a = PasswordHasher.hash(chars(PASSWORD));
        String b = PasswordHasher.hash(chars(PASSWORD));
        return !a.equals(b) && a.startsWith("pbkdf2-sha256$600000$")
                && PasswordHasher.verify(chars(PASSWORD), a);
    }

    private static int failuresOf(String name) {
        return ((Number) single("SELECT failed_attempts FROM users "
                + "WHERE username = ?", name)).intValue();
    }

    private static String statusOf(String name) {
        return (String) single("SELECT last_login_status FROM users "
                + "WHERE username = ?", name);
    }

    private static boolean loggedDesc(String event, String username,
            String descPart) {
        return single("SELECT timestamp FROM logs WHERE event = ? "
                + "AND username = ? AND instr(desc, ?) > 0 "
                + "AND timestamp IS NOT NULL LIMIT 1",
                event, username, descPart) != null;
    }

    private static boolean logged(String event, String username) {
        return single("SELECT timestamp FROM logs WHERE event = ? "
                + "AND username = ? AND timestamp IS NOT NULL LIMIT 1",
                event, username) != null;
    }

    private static boolean denied(Runnable action) {
        try {
            action.run();
            return false;
        } catch (AccessDeniedException ex) {
            return true;
        }
    }

    private static boolean rejected(Runnable action) {
        return failsWith(action, ValidationException.class);
    }

    private static boolean failsWith(Runnable action,
            Class<? extends RuntimeException> type) {
        try {
            action.run();
            return false;
        } catch (RuntimeException ex) {
            return type.isInstance(ex);
        }
    }

    private static String messageOf(Runnable action) {
        try {
            action.run();
            return "";
        } catch (RuntimeException ex) {
            return String.valueOf(ex.getMessage());
        }
    }

    private static long time(Runnable action) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < 3; i++) {
            long start = System.nanoTime();
            action.run();
            best = Math.min(best, System.nanoTime() - start);
        }
        return best;
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static String repeat(String value, int times) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < times; i++) {
            builder.append(value);
        }
        return builder.toString();
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title);
    }

    private static void check(String description, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("PASS  " + description);
        } else {
            failed++;
            System.out.println("FAIL  " + description);
        }
    }
}
