package Controller;

import java.math.BigDecimal;
import java.util.Arrays;

public class Validation {
    public static final int MAX_STOCK = 1_000_000;
    public static final long MAX_PRICE_CENTS = 100_000_000L;

    private Validation() {
    }

    public static boolean validUsername(String value) {
        return value != null
                && value.matches("[A-Za-z0-9]{3,32}");
    }

    public static String username(String value) {
        if (!validUsername(value)) {
            throw new IllegalArgumentException(
                    "Username must contain 3-32 letters or digits.");
        }

        return value;
    }

    public static String productName(String value) {
        if (value == null
                || !value.matches("[A-Za-z0-9]{1,64}")) {
            throw new IllegalArgumentException(
                    "Product name must contain 1-64 letters or digits.");
        }

        return value;
    }

    public static String search(String value) {
        if (value == null
                || (!value.isEmpty()
                && !value.matches("[A-Za-z0-9]{1,64}"))) {
            throw new IllegalArgumentException(
                    "Search must contain at most 64 letters or digits.");
        }

        return value;
    }

    public static void password(
            char[] password, char[] confirmation) {

        if (password == null
                || password.length < 12
                || password.length > 128) {
            throw new IllegalArgumentException(
                    "Password must contain 12-128 characters.");
        }

        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;

        for (char character : password) {
            if (character < 33 || character > 126) {
                throw new IllegalArgumentException(
                        "Use printable characters without spaces.");
            }

            boolean isUpper =
                    character >= 'A' && character <= 'Z';

            boolean isLower =
                    character >= 'a' && character <= 'z';

            boolean isDigit =
                    character >= '0' && character <= '9';

            upper |= isUpper;
            lower |= isLower;
            digit |= isDigit;
            symbol |= !isUpper && !isLower && !isDigit;
        }

        if (!upper || !lower || !digit || !symbol) {
            throw new IllegalArgumentException(
                    "Use uppercase, lowercase, digits, and symbols.");
        }

        if (confirmation == null
                || !Arrays.equals(password, confirmation)) {
            throw new IllegalArgumentException(
                    "Passwords do not match.");
        }
    }

    public static int integer(
            String value, int minimum, int maximum) {

        if (value == null
                || !value.matches("(0|[1-9][0-9]{0,6})")) {
            throw new IllegalArgumentException(
                    "Enter a valid whole number.");
        }

        int result = Integer.parseInt(value);

        if (result < minimum || result > maximum) {
            throw new IllegalArgumentException(
                    "Number is outside the allowed range.");
        }

        return result;
    }

    public static long price(String value) {
        if (value == null
                || !value.matches(
                        "(0|[1-9][0-9]{0,6})(\\.[0-9]{1,2})?")) {
            throw new IllegalArgumentException(
                    "Enter a valid price with at most two decimal places.");
        }

        long cents = new BigDecimal(value)
                .movePointRight(2)
                .longValueExact();

        if (cents < 0 || cents > MAX_PRICE_CENTS) {
            throw new IllegalArgumentException(
                    "Price is outside the allowed range.");
        }

        return cents;
    }

    public static void role(int role) {
        if (role < 1 || role > 5) {
            throw new IllegalArgumentException(
                    "Role must be between 1 and 5.");
        }
    }

    public static void id(int id) {
        if (id <= 0) {
            throw new IllegalArgumentException(
                    "Select a valid record.");
        }
    }
}
