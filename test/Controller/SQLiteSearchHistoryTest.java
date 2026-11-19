package Controller;

import Model.History;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

public final class SQLiteSearchHistoryTest {

    private static int passed;

    private SQLiteSearchHistoryTest() {
    }

    public static void main(String[] args) throws Exception {
        Path temporaryDirectory =
                Paths.get(System.getProperty("java.io.tmpdir"))
                        .toRealPath();
        Path testDatabase =
                new File("database.db").getCanonicalFile().toPath();
        Path testDirectory = testDatabase.getParent();
        if (!testDatabase.startsWith(temporaryDirectory)
                || !testDirectory.getFileName().toString()
                        .startsWith("history-search-dao-")) {
            throw new IllegalStateException(
                    "Run this test only from a disposable database copy "
                    + "inside the system temporary directory.");
        }

        SQLite sqlite = new SQLite();
        String operator = "SearchDaoManager"
                + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        char[] password = "SearchAdmin!7312".toCharArray();
        seedHistory(operator, password);

        try {
            if (!sqlite.login(operator, password).isSuccessful()) {
                throw new AssertionError("Could not authenticate test manager.");
            }

            ArrayList<History> lowerCase = sqlite.searchHistory("admin");
            check("admin matches the complete username",
                    lowerCase.size() == 1
                    && "admin".equals(lowerCase.get(0).getUsername()));

            check("Admin matches the same username ignoring case",
                    sameResult(lowerCase, sqlite.searchHistory("Admin")));
            check("ADMIN matches the same username ignoring case",
                    sameResult(lowerCase, sqlite.searchHistory("ADMIN")));

            check("adminnnnnn does not partially match admin",
                    sqlite.searchHistory("adminnnnnn").isEmpty());
            check("adm does not prefix-match admin",
                    sqlite.searchHistory("adm").isEmpty());
            check("dmin does not substring-match admin",
                    sqlite.searchHistory("dmin").isEmpty());

            check("product-name substring search remains supported",
                    sqlite.searchHistory("Wid").size() == 2);
            check("product-name search ignores case",
                    sqlite.searchHistory("wid").size() == 2
                    && sqlite.searchHistory("WIDGETONE").size() == 1
                    && sqlite.searchHistory("widgettwo").size() == 1);

            boolean invalidCharactersRejected = false;
            try {
                sqlite.searchHistory("admin!");
            } catch (IllegalArgumentException ex) {
                invalidCharactersRejected = true;
            }
            check("invalid search characters remain rejected",
                    invalidCharactersRejected);

            boolean overlongSearchRejected = false;
            try {
                sqlite.searchHistory(repeat('A', 65));
            } catch (IllegalArgumentException ex) {
                overlongSearchRejected = true;
            }
            check("search length remains capped at 64 characters",
                    overlongSearchRejected
                    && sqlite.searchHistory(repeat('A', 64)) != null);

            check("validation failures retain timestamped security logs",
                    hasTimestampedSearchValidationLogs(operator));
            System.out.println("RESULT: " + passed + " DAO checks passed");
        } finally {
            Arrays.fill(password, '\0');
            sqlite.logout();
        }
    }

    private static void seedHistory(String operator, char[] password)
            throws Exception {
        try (Connection conn =
                DriverManager.getConnection("jdbc:sqlite:database.db")) {
            conn.setAutoCommit(false);
            try (Statement statement = conn.createStatement()) {
                statement.executeUpdate("DELETE FROM history");
            }
            try (PreparedStatement user = conn.prepareStatement(
                    "INSERT INTO users(username,password,role,locked,"
                    + "failed_attempts) VALUES(?,?,4,0,0)")) {
                user.setString(1, operator);
                user.setString(2, PasswordHasher.hash(password));
                user.executeUpdate();
            }
            try (PreparedStatement history = conn.prepareStatement(
                    "INSERT INTO history(username,name,stock,timestamp,"
                    + "user_id,product_id,unit_price_cents) "
                    + "VALUES(?,?,1,?,NULL,NULL,NULL)")) {
                insertHistory(history, "admin", "WidgetOne");
                insertHistory(history, "otheruser", "WidgetTwo");
            }
            conn.commit();
        }
    }

    private static void insertHistory(
            PreparedStatement statement, String username, String product)
            throws Exception {
        statement.setString(1, username);
        statement.setString(2, product);
        statement.setString(3, Instant.now().toString());
        statement.executeUpdate();
    }

    private static boolean sameResult(
            ArrayList<History> expected, ArrayList<History> actual) {
        return expected.size() == 1
                && actual.size() == 1
                && expected.get(0).getId() == actual.get(0).getId();
    }

    private static boolean hasTimestampedSearchValidationLogs(
            String operator) throws Exception {
        String sql = "SELECT timestamp FROM logs WHERE event = ? "
                + "AND username = ? AND desc LIKE ?";
        try (Connection conn =
                DriverManager.getConnection("jdbc:sqlite:database.db");
                PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.setString(1, "VALIDATION_FAILURE");
            statement.setString(2, operator);
            statement.setString(
                    3, "Rejected input for operation: search-history%");
            try (ResultSet rs = statement.executeQuery()) {
                int count = 0;
                while (rs.next()) {
                    if (rs.getString("timestamp") == null) {
                        return false;
                    }
                    count++;
                }
                return count >= 2;
            }
        }
    }

    private static String repeat(char character, int length) {
        char[] chars = new char[length];
        Arrays.fill(chars, character);
        return new String(chars);
    }

    private static void check(String description, boolean condition) {
        if (!condition) {
            throw new AssertionError(description);
        }
        passed++;
        System.out.println("PASS: " + description);
    }
}
