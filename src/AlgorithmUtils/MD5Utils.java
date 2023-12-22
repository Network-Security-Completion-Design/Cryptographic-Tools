package AlgorithmUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Utils {
    /**
     * 提供16位和32位md5加密
     *
     * @param src
     *            明文
     * @param length
     *            加密长度 16或32位加密，默认32位
     */
    public static String MD5(String src, int length) {
        try {
            if (null == src) {
                return null;
            }
            String returnValue;
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(src.getBytes());
            byte[] b = md.digest();
            int i;
            StringBuilder buf = new StringBuilder();
            for (byte value : b) {
                i = value;
                if (i < 0) {
                    i += 256;
                }
                if (i < 16) {
                    buf.append("0");
                }
                buf.append(Integer.toHexString(i));
            }
            switch (length) {
                // 16位的加密
                case 16:
                    returnValue = buf.substring(8, 24);
                    break;
                // 32位的加密
                case 32:
                    // 默认32位的加密
                default:
                    returnValue = buf.toString();
                    break;
            }
            return returnValue;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }



    public static void main(String[] args) {
        String srcStr = "This is a test！";
        System.out.println("原始信息：" + srcStr);
        System.out.println("MD5摘要值(摘要长度16位)：" + MD5(srcStr, 16));
        System.out.println("MD5摘要值(摘要长度32位)：" + MD5(srcStr, 32));
    }
}
