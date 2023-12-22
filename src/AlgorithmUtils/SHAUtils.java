package AlgorithmUtils;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAUtils {
    public static void main(String[] args) {
        String input = "Hello, World!";

        System.out.println("SHA-1: " + sha1(input));
        System.out.println("SHA-256: " + sha256(input));
        System.out.println("SHA-512: " + sha512(input));
        System.out.println("SHA3-256: " + sha3(input));
    }

    public static String sha1(String input) {
        return hash(input, "SHA-1");
    }

    public static String sha256(String input) {
        return hash(input, "SHA-256");
    }

    public static String sha512(String input) {
        return hash(input, "SHA-512");
    }

    public static String sha3(String input) {
        try {
            Digest digest = new SHA3Digest(256);
            byte[] hashBytes = new byte[digest.getDigestSize()];

            byte[] inputBytes = input.getBytes();
            digest.update(inputBytes, 0, inputBytes.length);
            digest.doFinal(hashBytes, 0);

            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String hash(String input, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }
}