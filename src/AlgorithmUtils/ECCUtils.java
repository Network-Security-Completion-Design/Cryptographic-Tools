package AlgorithmUtils;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class ECCUtils {

    /**
     * 生成密钥对(公钥和私钥)
     */
    public static KeyPair initKey(int keySize, String KEY_ALGORITHM) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(keySize);
        return keyPairGen.generateKeyPair();
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     */
    public static String encryptByPublicKey(String data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        Security.addProvider(new BouncyCastleProvider());
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(x509KeySpec));
        return Base64.encodeBase64String(cipher.doFinal(data.getBytes()));
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     */
    public static String decryptByPrivateKey(String encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(pkcs8KeySpec));
        return Base64.encodeBase64String(cipher.doFinal(Base64.decodeBase64(encryptedData)));
    }


    public static String Decrypt(String encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(pkcs8KeySpec));
        return new String(cipher.doFinal(Base64.decodeBase64(encryptedData)));
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param content     已加密数据 base64
     * @param priKey      私钥(BASE64编码)
     * @param signatureAl 签名算法
     */
    public static String Sign(String content, String priKey, String signatureAl) throws Exception {
        byte[] priKeyBytes = Base64.decodeBase64(priKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPrivateKey privateK = (ECPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        Signature sign = Signature.getInstance(signatureAl, "BC");
        sign.initSign(privateK);
        sign.update(Base64.decodeBase64(content));
        byte[] signatureBytes = sign.sign();
        return Base64.encodeBase64String(signatureBytes);
    }

    public static boolean Verify(String content, String signature, String publicKey, String signatureAl) throws Exception {
        byte[] pubKeyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPublicKey publicK = (ECPublicKey) keyFactory.generatePublic(x509KeySpec);
        Signature verifySignature = Signature.getInstance(signatureAl, "BC");
        verifySignature.initVerify(publicK);
        verifySignature.update(Base64.decodeBase64(content));
        return verifySignature.verify(Base64.decodeBase64(signature));
    }



    public static void main(String[] args) {
        try {
            // 初始化获取公钥和私钥
            KeyPair keypair = initKey(256, "EC");

            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            String publicKeyBase64 = Base64.encodeBase64String(publicKey.getEncoded());
            String privateKeyBase64 = Base64.encodeBase64String(privateKey.getEncoded());

            // 生成固定公钥私钥
            System.out.println("公钥：" + publicKeyBase64);
            System.out.println("\n私钥：" + privateKeyBase64);

            String con = "这是一条测试加密的数据，哈哈哈哈";
            System.out.println("\n椭圆曲线明文：" + con);

            // 加密
            String content = encryptByPublicKey(con, publicKeyBase64);
            System.out.println("\n密文：" + content);

            // 解密
            String contentDe = decryptByPrivateKey(content, privateKeyBase64);

            String deStr = new String(Base64.decodeBase64(contentDe));
            System.out.println("\n解密明文：" + deStr);

            List<String> algorithm = new ArrayList<>();
            algorithm.add("SHA256withECDSA");
            algorithm.add("SHA384withECDSA");
            algorithm.add("SHA3-256withECDSA");
            algorithm.add("SHA3-384withECDSA");
            algorithm.add("SHA3-512withECDSA");

            System.out.println();

            for (String i : algorithm) {

                System.out.println("\nalgorithm: " + i);

                // 签名
                String sign = Sign(content, privateKeyBase64, i);
                System.out.println("\n签名：" + sign);

                // 验签
                boolean Ver = Verify(content, sign, publicKeyBase64, i);
                System.out.println("\n验证：" + Ver);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
