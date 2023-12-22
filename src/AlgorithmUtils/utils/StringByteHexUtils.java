package AlgorithmUtils.utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 字符串、字节、进制转换
 *
 * @author 鬼面书生
 *
 */
public class StringByteHexUtils {
    // 十六进制位
    public static char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * 字节数组转16进制
     *
     * @param bytes 需要转换的byte数组
     * @return 转换后的Hex字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            String hexStr = Integer.toHexString(aByte & 0xFF);
            if (hexStr.length() < 2) {
                sb.append(0);
            }
            sb.append(hexStr);
        }
        return sb.toString();
    }

    /**
     * 十六进制字符串转byte数组
     *
     * @param hexStr 待转换的Hex字符串
     * @return 转换后的byte数组结果
     */
    public static byte[] hexToByteArray(String hexStr) {
        int hexLength = hexStr.length();
        byte[] result;
        if (hexLength % 2 == 1) {
            // 奇数
            hexLength++;
            result = new byte[(hexLength / 2)];
            hexStr = "0" + hexStr;
        } else {
            // 偶数
            result = new byte[(hexLength / 2)];
        }
        int j = 0;
        for (int i = 0; i < hexLength; i += 2) {
            result[j] = hexToByte(hexStr.substring(i, i + 2));
            j++;
        }
        return result;
    }

    // SecretKey转化为String
    public static String secretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // String转化为SecretKey
    public static SecretKey stringToSecretKey(String secretKeyString, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
        return new SecretKeySpec(decodedKey, algorithm);
    }



    public static boolean isValidDecryptionResult(String str) {

        for (int i = 0; i < str.length(); i++) {

            char c = str.charAt(i);

            if ((int) c == 0xfffd) {
                return false;
            }
        }
        return true;

    }



    public static String keyPairToString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String publicKeyStr = org.apache.commons.codec.binary.Base64.encodeBase64String(publicKey.getEncoded());
        String privateKeyStr = org.apache.commons.codec.binary.Base64.encodeBase64String(privateKey.getEncoded());

        return publicKeyStr + "|" + privateKeyStr;
    }

    public static KeyPair stringToKeyPair(String keyPairStr) throws GeneralSecurityException {
        String[] keyParts = keyPairStr.split("\\|");
        String publicKeyStr = keyParts[0];
        String privateKeyStr = keyParts[1];

        byte[] publicKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(publicKeyStr);
        byte[] privateKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(privateKeyStr);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }


    /**
     * 十六进制字符串转字节
     *
     * @param hexStr 待转换的Hex字符串
     * @return 转换后的byte
     */
    public static byte hexToByte(String hexStr) {
        return (byte) Integer.parseInt(hexStr, 16);
    }

    /**
     * 字符串转换unicode
     */
    public static String string2Unicode(String string) {
        StringBuilder unicode = new StringBuilder();
        for (int i = 0; i < string.length(); i++) {
            // 取出每一个字符
            char c = string.charAt(i);
            // 转换为unicode
            unicode.append("\\u").append(Integer.toHexString(c));
        }
        return unicode.toString();
    }

    /**
     * unicode字符串转16进制字符串
     *
     * @param s
     * @return
     */
    public static String unicodeStrTo16(String s) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            int ch = (int) s.charAt(i);
            str.append(Integer.toHexString(ch));
        }
        return str.toString();
    }

    public static byte[] toByteArray(int i) {
        byte[] byteArray = new byte[4];
        byteArray[0] = (byte) (i >>> 24);
        byteArray[1] = (byte) ((i & 0xFFFFFF) >>> 16);
        byteArray[2] = (byte) ((i & 0xFFFF) >>> 8);
        byteArray[3] = (byte) (i & 0xFF);
        return byteArray;
    }

    /**
     * 字节转16进制
     *
     * @param b
     * @return
     */
    private static String byteToHexString(byte b) {
        int n = b;
        if (n < 0)
            n = 256 + n;
        int d1 = n / 16;
        int d2 = n % 16;
        return String.valueOf(hexDigits[d1]) + hexDigits[d2];
    }

    /**
     * 字节数组转16进制
     *
     * @param b
     * @return
     */
    public static String byteArrayToHexString(byte[] b) {
        StringBuilder resultSb = new StringBuilder();
        for (byte value : b) {
            resultSb.append(byteToHexString(value));
        }
        return resultSb.toString();
    }

    /**
     * 字节数组转16进制
     *
     * @param b
     */

    public static String byteArray2HexString(byte[] b) {
        StringBuilder str = new StringBuilder();
        for (byte value : b) {
            String hex = Integer.toHexString(value & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            str.append(hex.toUpperCase());
        }
        return str.toString();
    }

    public static byte[] long2bytes(long l) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (l >>> ((7 - i) * 8));
        }
        return bytes;
    }
}
