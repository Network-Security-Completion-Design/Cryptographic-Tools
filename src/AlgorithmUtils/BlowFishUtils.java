package AlgorithmUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Blowfish/ECB/NoPadding 工具
 */
public class BlowFishUtils {

    public static void main(String[] ags) {

        String data = "This is a 测试！";
        System.out.println("原始字符串:" + data);

        String key = String.valueOf(new SecureRandom().nextInt());

        //加密
        String encrypt = encodingToBase64(key, data);
        System.out.println("\n加密结果:" + encrypt);

        //解密
        String decodingByBase64 = decodingByBase64(key, encrypt);
        System.out.println("\n解密结果:" + decodingByBase64);

        System.out.println("\n是否完全相等:" + data.equals(decodingByBase64));

    }


    /**
     * Blowfish/ECB/NoPadding 加密并输出base64
     * 不足8倍数自动尾部补充0
     *
     * @param key  密钥key
     * @param data 要加密的字符串
     * @return 加密后的字符串
     */
    public static String encodingToBase64(String key, String data) {
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] dataBytes = data.getBytes();
            int length = dataBytes.length;
            //计算需填充长度
            if (length % blockSize != 0) {
                length = length + (blockSize - (length % blockSize));
            }
            byte[] plaintext = new byte[length];
            //填充
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return java.util.Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Blowfish/ECB/NoPadding 解密base64的字符串
     * 自动去除尾部补充的0
     *
     * @param key 密钥key
     * @param str 要解密的字符串
     * @return 解密后的字符串
     */
    public static String decodingByBase64(String key, String str) {

        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "Blowfish");
        Cipher cipher;

        String cipherInstName = "Blowfish/ECB/NoPadding";
        byte[] doFinal;

        try {
            cipher = Cipher.getInstance(cipherInstName);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            doFinal = cipher.doFinal(java.util.Base64.getDecoder().decode(str.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        int zeroIndex = doFinal.length;
        for (int i = doFinal.length - 1; i > 0; i--) {
            if (doFinal[i] == (byte) 0) {
                zeroIndex = i;
            } else {
                break;
            }
        }
        // 删除末尾填充的0
        doFinal = Arrays.copyOf(doFinal, zeroIndex);

        return new String(doFinal, StandardCharsets.UTF_8);
    }

    public static String DecodingByBase64(String key, String str) {

        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "Blowfish");
        Cipher cipher;

        String cipherInstName = "Blowfish/ECB/NoPadding";
        byte[] doFinal;

        try {
            cipher = Cipher.getInstance(cipherInstName);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            doFinal = cipher.doFinal(java.util.Base64.getDecoder().decode(str.getBytes()));
        } catch (Exception e) {
            return "解密失败，请检查密钥和密文是否配套！";
        }

        int zeroIndex = doFinal.length;
        for (int i = doFinal.length - 1; i > 0; i--) {
            if (doFinal[i] == (byte) 0) {
                zeroIndex = i;
            } else {
                break;
            }
        }
        // 删除末尾填充的0
        doFinal = Arrays.copyOf(doFinal, zeroIndex);

        return new String(doFinal, StandardCharsets.UTF_8);
    }

}
