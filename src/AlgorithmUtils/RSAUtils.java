package AlgorithmUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;

public class RSAUtils {
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair(KEY_SIZE);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("生成的公钥：" + publicKey);
        System.out.println("生成的私钥：" + privateKey);

        // 数据加密和解密示例
        String plainText = "Hello, RSA!";
        byte[] encryptedData = encrypt(plainText.getBytes(StandardCharsets.UTF_8), publicKey);
        byte[] decryptedData = decrypt(encryptedData, privateKey);
        System.out.println("加密后的数据：" + Arrays.toString(encryptedData));
        System.out.println("解密后的数据：" + new String(decryptedData, StandardCharsets.UTF_8));

        // 数字签名和验证示例
        byte[] signature = sign(plainText.getBytes(StandardCharsets.UTF_8), privateKey);
        boolean verified = verify(plainText.getBytes(StandardCharsets.UTF_8), signature, publicKey);
        System.out.println("数字签名：" + Arrays.toString(signature));
        System.out.println("验证结果：" + verified);
    }

    // 生成密钥对
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    // 加密
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // 解密
    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // 数字签名
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // 验证数字签名
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
