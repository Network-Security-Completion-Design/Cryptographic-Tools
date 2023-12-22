package AlgorithmUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class IDEAUtils {

    private static final String ALGORITHM = "IDEA";

    public static SecretKey generateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, "BC");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public static SecretKey GenKey(String input) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] inputBytes = input.getBytes();
        byte[] hashedBytes = sha256.digest(inputBytes);

        byte[] keyBytes = new byte[16];
        System.arraycopy(hashedBytes, 0, keyBytes, 0, keyBytes.length);

        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] encrypt(byte[] input, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥
            SecretKey key = generateKey();

            // 原始数据
            String plainText = "Hello, World!";
            byte[] plainBytes = plainText.getBytes();

            // 加密
            byte[] encryptedBytes = encrypt(plainBytes, key);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            // 解密
            byte[] decryptedBytes = decrypt(Base64.getDecoder().decode(encryptedText), key);
            String decryptedText = new String(decryptedBytes);

            // 输出结果
            System.out.println("原始数据: " + plainText);
            System.out.println("加密后数据: " + encryptedText);
            System.out.println("解密后数据: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
