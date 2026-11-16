package Controller;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordHasher {

    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);

        byte[] key = derive(password, salt, ITERATIONS);

        try {
            return "pbkdf2-sha256$"
                    + ITERATIONS + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(key);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public static boolean isHash(String encoded) {
        if (encoded == null) {
            return false;
        }

        try {
            String[] parts = encoded.split("\\$", -1);

            if (parts.length != 4
                    || !"pbkdf2-sha256".equals(parts[0])) {
                return false;
            }

            int iterations = Integer.parseInt(parts[1]);

            return iterations >= ITERATIONS
                    && iterations <= 2_000_000
                    && Base64.getDecoder().decode(parts[2]).length == 16
                    && Base64.getDecoder().decode(parts[3]).length == 32;

        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    public static boolean verify(char[] password, String encoded) {
        if (password == null || !isHash(encoded)) {
            return false;
        }

        String[] parts = encoded.split("\\$", -1);

        int iterations = Integer.parseInt(parts[1]);
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        byte[] actual = derive(password, salt, iterations);

        try {
            return MessageDigest.isEqual(expected, actual);
        } finally {
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static byte[] derive(
            char[] password, byte[] salt, int iterations) {

        PBEKeySpec specification =
                new PBEKeySpec(password, salt, iterations, KEY_BITS);

        try {
            return SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification)
                    .getEncoded();

        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(
                    "Password processing unavailable.");

        } finally {
            specification.clearPassword();
        }
    }
}
