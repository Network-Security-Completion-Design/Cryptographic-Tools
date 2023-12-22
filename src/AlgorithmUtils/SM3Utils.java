package AlgorithmUtils;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;


public class SM3Utils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] sm3(byte[] srcData) {
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(hash, 0);
        return hash;
    }

    public static String sm3Hex(byte[] srcData) {
        byte[] hash = sm3(srcData);
        return org.apache.commons.codec.binary.Hex.encodeHexString(hash);
    }

    public static byte[] hmacSm3(byte[] key, byte[] srcData) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(srcData, 0, srcData.length);
        byte[] hash = new byte[mac.getMacSize()];
        mac.doFinal(hash, 0);
        return hash;
    }

    public static String hmacSm3Hex(byte[] key, byte[] srcData) {
        byte[] hash = hmacSm3(key, srcData);
        return org.apache.commons.codec.binary.Hex.encodeHexString(hash);
    }

    public static byte[] sm3bc(byte[] srcData) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SM3", "BC");
        return messageDigest.digest(srcData);
    }

    public static String sm3bcHex(byte[] srcData) throws Exception {
        byte[] hash = sm3bc(srcData);
        return org.apache.commons.codec.binary.Hex.encodeHexString(hash);
    }



    public static void main(String[] args) throws Exception {
        String test = "This is a 测试！";

        System.out.println("SM3 待摘要数据：" + test);

        String s = SM3Utils.sm3Hex(test.getBytes());
        System.out.println("\nSM3 摘要值：" + s);
        String s2 = SM3Utils.hmacSm3Hex("AA".getBytes(), test.getBytes());
        System.out.println("\nSM3 摘要值：" + s2);

    }

}
