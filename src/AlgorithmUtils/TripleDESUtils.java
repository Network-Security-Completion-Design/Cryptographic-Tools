package AlgorithmUtils;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class TripleDESUtils {
    public static void main(String[] args) {
        try {

            // 1. 生成密钥
            SecretKey secretKey = genkey();

            String plainText = "Hello, Triple DES!";

            // 4. 加密
            byte[] encrypted = encrypt(plainText, secretKey);

            // 5. 解密
            String decrypted = decrypt(encrypted, secretKey);

            System.out.println("Original: " + plainText);
            System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));
            System.out.println("Decrypted: " + decrypted);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }



    public static SecretKey genkey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        return keyGenerator.generateKey();
    }


    public static SecretKey GenKey(String seed) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        if (seed.length() < 24) {
            // 如果seed长度不足24字节，则补全seed至24字节
            seed = String.format("%-24s", seed);
        } else if (seed.length() > 24) {
            // 如果seed长度超过24字节，则截取前24字节作为seed
            seed = seed.substring(0, 24);
        }

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        KeySpec keySpec = new DESedeKeySpec(seed.getBytes());

        return keyFactory.generateSecret(keySpec);
    }



    // 加密函数
    public static byte[] encrypt(String input, SecretKey secretKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        Cipher encryptCipher = Cipher.getInstance("DESede");

        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return encryptCipher.doFinal(input.getBytes());
    }



    // 解密函数
    public static String decrypt(byte[] input, SecretKey secretKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        Cipher decryptCipher = Cipher.getInstance("DESede");

        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = decryptCipher.doFinal(input);

        return new String(decryptedBytes);
    }
}
