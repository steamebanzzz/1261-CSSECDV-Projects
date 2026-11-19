package Controller;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Whitelist ("accept known good") input validation. Every rule REJECTS the
 * whole input when it fails; nothing is trimmed, escaped or otherwise
 * "cleaned". Failures raise ValidationException with a fixed message that
 * names the field and rule but never echoes the rejected value.
 */
public final class Validation {

    public static final int USERNAME_MIN = 3;
    public static final int USERNAME_MAX = 32;
    public static final int PASSWORD_MIN = 12;
    public static final int PASSWORD_MAX = 128;
    public static final int NAME_MAX = 64;
    public static final int MAX_STOCK = 1_000_000;
    public static final long MAX_PRICE_CENTS = 100_000_000L;

    private static final Pattern USERNAME =
            Pattern.compile("^[A-Za-z0-9]{3,32}$");
    private static final Pattern PRODUCT_NAME =
            Pattern.compile("^[A-Za-z0-9]{1,64}$");
    private static final Pattern SEARCH =
            Pattern.compile("^[A-Za-z0-9]{0,64}$");
    private static final Pattern WHOLE_NUMBER =
            Pattern.compile("^(0|[1-9][0-9]{0,6})$");
    private static final Pattern PRICE =
            Pattern.compile("^(0|[1-9][0-9]{0,6})(\\.[0-9]{1,2})?$");

    private Validation() {
    }

    public static boolean validUsername(String value) {
        return value != null && USERNAME.matcher(value).matches();
    }

    public static String username(String value) {
        if (!validUsername(value)) {
            throw new ValidationException(
                    "Username must only contain alphanumeric characters and be of length 3 to 32.");
        }
        return value;
    }

    public static String productName(String value) {
        if (value == null || !PRODUCT_NAME.matcher(value).matches()) {
            throw new ValidationException(
                    "Product name must only contain alphanumeric characters and be of length 1 to 64.");
        }
        return value;
    }

    public static String search(String value) {
        if (value == null || !SEARCH.matcher(value).matches()) {
            throw new ValidationException(
                    "Search must only contain alphanumeric characters and at most be of 64 length.");
        }
        return value;
    }

    /**
     * Length rule for passwords that are only being CHECKED (login and
     * re-authentication). The complexity policy is not applied here so that
     * nothing about the stored password is revealed.
     */
    public static boolean validCredentialLength(char[] password) {
        return password != null
                && password.length >= 1
                && password.length <= PASSWORD_MAX;
    }

    /** Password policy for NEW passwords (registration / change). */
    public static void password(char[] password, char[] confirmation) {
        if (password == null
                || password.length < PASSWORD_MIN
                || password.length > PASSWORD_MAX) {
            throw new ValidationException(
                    "Password must contain 12-128 characters.");
        }

        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;

        for (char character : password) {
            if (character < 33 || character > 126) {
                throw new ValidationException(
                        "Use printable characters without spaces.");
            }

            boolean isUpper = character >= 'A' && character <= 'Z';
            boolean isLower = character >= 'a' && character <= 'z';
            boolean isDigit = character >= '0' && character <= '9';

            upper |= isUpper;
            lower |= isLower;
            digit |= isDigit;
            symbol |= !isUpper && !isLower && !isDigit;
        }

        if (!upper || !lower || !digit || !symbol) {
            throw new ValidationException(
                    "Password must include uppercase, lowercase, digits, "
                    + "and symbols.");
        }

        if (confirmation == null || !Arrays.equals(password, confirmation)) {
            throw new ValidationException("Passwords do not match.");
        }
    }

    public static int integer(String value, int minimum, int maximum) {
        if (value == null || !WHOLE_NUMBER.matcher(value).matches()) {
            throw new ValidationException("Enter a valid whole number.");
        }

        int result = Integer.parseInt(value);
        if (result < minimum || result > maximum) {
            throw new ValidationException(
                    "Number must be between " + minimum + " and "
                    + maximum + ".");
        }
        return result;
    }

    public static void range(int value, int minimum, int maximum) {
        if (value < minimum || value > maximum) {
            throw new ValidationException(
                    "Number must be between " + minimum + " and "
                    + maximum + ".");
        }
    }

    public static long price(String value) {
        if (value == null || !PRICE.matcher(value).matches()) {
            throw new ValidationException(
                    "Enter a valid price with at most two decimal places.");
        }

        long cents = new BigDecimal(value).movePointRight(2).longValueExact();
        priceCents(cents);
        return cents;
    }

    public static void priceCents(long cents) {
        if (cents < 1 || cents > MAX_PRICE_CENTS) {
            throw new ValidationException(
                    "Price must be between 0.01 and 1000000.00.");
        }
    }

    public static void role(int role) {
        if (role < 1 || role > 5) {
            throw new ValidationException("Role must be between 1 and 5.");
        }
    }
}
