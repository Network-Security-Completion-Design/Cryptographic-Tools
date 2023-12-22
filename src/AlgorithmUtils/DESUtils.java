package AlgorithmUtils;

import AlgorithmUtils.utils.StringByteHexUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 * DES加密说明
 * <p>
 * DES是一种对称加密算法，对称加密即：加密和解密使用相同密钥的算法。
 * <p>
 * 注意：DES加密和解密过程中，密钥长度必须是8的倍数;
 *
 * @author 鬼面书生
 *
 */
public class DESUtils {

    /**
     * 加密过程
     *
     * @param src
     *            原始信息
     * @param password
     *            密码
     */
    public static byte[] encrypt(String src, String password) {

        try {
            // DES算法要求有一个可信任的随机数源
            SecureRandom secureRandom = new SecureRandom();

            // 创建一个DESKeySpec对象
            DESKeySpec desKeySpec = new DESKeySpec(password.getBytes());

            // 创建密匙工厂
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");

            // 将密码利用密匙工厂转换成密匙
            SecretKey securekey = secretKeyFactory.generateSecret(desKeySpec);

            // 创建Cipher对象，用于完成实际加密操作
            Cipher cipher = Cipher.getInstance("DES");

            // 用密匙初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, securekey, secureRandom);

            // 执行加密操作并返回密文
            return cipher.doFinal(src.getBytes());

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return null;

    }

    /**
     *
     * 解密
     *
     * @param src
     *            密文字节数组 byte[]
     *
     * @param password
     *            密码 String
     *
     * @return byte[]
     *
     *
     */

    public static byte[] decrypt(byte[] src, String password) throws Exception {

        // DES算法要求有一个可信任的随机数源
        SecureRandom random = new SecureRandom();

        // 创建一个DESKeySpec对象
        DESKeySpec desKey = new DESKeySpec(password.getBytes());

        // 创建一个密匙工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");

        // 将DESKeySpec对象转换成SecretKey对象
        SecretKey securekey = keyFactory.generateSecret(desKey);

        // Cipher对象，用于完成实际解密操作
        Cipher cipher = Cipher.getInstance("DES");

        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, random);

        // 开始解密
        return cipher.doFinal(src);

    }

    public static SecretKey generateDESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);

        return keyGenerator.generateKey();
    }



    public static SecretKey GenKey(String input) throws NoSuchAlgorithmException {
        byte[] inputBytes = input.getBytes();

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        KeySpec keySpec;
        try {
            keySpec = new DESKeySpec(inputBytes);
            return keyFactory.generateSecret(keySpec);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) throws Exception {
        // 待加密内容
        String srcStr = "春宵一刻值千金，花有清香月有阴；歌管楼台声细细，秋千院落夜沉沉！";

        String key = String.valueOf(generateDESKey());

        System.out.println(key);

        byte[] encriptMsg = DESUtils.encrypt(srcStr, key);
        String enc = null;
        if (encriptMsg != null) {
            enc = new String(encriptMsg);
        }
        System.out.println("明文信息：" + srcStr);
        System.out.println("DES加密后(byte数组)：" + Arrays.toString(encriptMsg));
        System.out.println("DES加密后密文：" + enc);
        String bytesToHexStr = null;
        if (encriptMsg != null) {
            bytesToHexStr = StringByteHexUtils.bytesToHex(encriptMsg);
        }
        System.out.println("DES加密后字节数组转16进制：" + bytesToHexStr);

        byte[] b = new byte[0];
        if (bytesToHexStr != null) {
            b = StringByteHexUtils.hexToByteArray(bytesToHexStr);
        }
        System.out.println("16进制转换成字节数组：" + Arrays.toString(b));
        System.out.println("16进制转换成字节数组后的密文：" + new String(b));

        // 将加密后的byte数据再进行base64加密，生成字符串。
        String encoded = Base64.getEncoder().encodeToString(encriptMsg);
        System.out.println("BASE64对DES加密后的字节数组再次加密后的密文：" + encoded);

        // 将base64加密后生成的字符串解密，还原成byte数组(密文)，供DES解密用
        byte[] decoded = Base64.getDecoder().decode(encoded);
        System.out.println("BASE64解密后的字节数组：" + Arrays.toString(decoded));
        System.out.println("BASE64解密后数组转换成的密码：" + new String(decoded));

        byte[] decryResult = DESUtils.decrypt(b, key);
        System.out.println("解密后：" + new String(decryResult));
        if (enc != null) {
            System.out.println("原始加密后密文与base64解密密文比较：" + enc.equals(new String(decoded)));
        }
        byte[] _decryResult = DESUtils.decrypt(decoded, key);
        System.out.println("DES利用密码串解密后：" + new String(_decryResult));
    }
}
