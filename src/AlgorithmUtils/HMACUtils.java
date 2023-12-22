package AlgorithmUtils;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACUtils {
    public static void main(String[] args) {

        String message = "hello";
        String key = "secret";

        /** HMAC **/
        try {

            String hmac = bytesToHex(HMACMD5(key, message));
            System.out.println("MD5: " + hmac);

            hmac = bytesToHex(HMACSHA1(key, message));
            System.out.println("\nSHA1: " + hmac);

            hmac = bytesToHex(HMACSHA256(key, message));
            System.out.println("\nSHA2-256: " + hmac);

            hmac = bytesToHex(HMACSHA384(key, message));
            System.out.println("\nSHA2-384: " + hmac);

            hmac = bytesToHex(HMACSHA512(key, message));
            System.out.println("\nSHA2-512: " + hmac);

            hmac = bytesToHex(HMACSHA3(key, message));
            System.out.println("\nSHA3-256: " + hmac);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

    }

    public static byte[] HMACSHA1(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha1 = Mac.getInstance("HmacSHA1");
        SecretKeySpec hmacKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        hmacSha1.init(hmacKey);
        return hmacSha1.doFinal(message.getBytes());
    }

    public static byte[] HMACSHA256(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec hmacKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        hmacSha256.init(hmacKey);
        return hmacSha256.doFinal(message.getBytes());
    }

    public static byte[] HMACMD5(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
        SecretKeySpec hmacKey = new SecretKeySpec(key.getBytes(), "HmacMD5");
        hmacMd5.init(hmacKey);
        return hmacMd5.doFinal(message.getBytes());
    }

    public static byte[] HMACSHA384(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha384 = Mac.getInstance("HmacSHA384");
        SecretKeySpec hmacKey = new SecretKeySpec(key.getBytes(), "HmacSHA384");
        hmacSha384.init(hmacKey);
        return hmacSha384.doFinal(message.getBytes());
    }

    public static byte[] HMACSHA512(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha512 = Mac.getInstance("HmacSHA512");
        SecretKeySpec hmacKey = new SecretKeySpec(key.getBytes(), "HmacSHA512");
        hmacSha512.init(hmacKey);
        return hmacSha512.doFinal(message.getBytes());
    }

    public static byte[] HMACSHA3(String message, String key) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        HMac hmac = new HMac(new SHA3Digest(256)); // SHA3-256 HMAC
        hmac.init(new KeyParameter(keyBytes));
        hmac.update(messageBytes, 0, messageBytes.length);

        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);

        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

}
