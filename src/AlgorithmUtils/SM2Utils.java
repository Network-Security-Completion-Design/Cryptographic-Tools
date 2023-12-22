package AlgorithmUtils;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SM2Utils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成国密公私钥对
     * <p>
     * <code>String[0]</code> 公钥
     * <p>
     * <code>String[1]</code> 私钥
     *
     * @return
     * @throws Exception
     */
    public static String[] generateSmKey() throws Exception {
        KeyPairGenerator keyPairGenerator = null;
        SecureRandom secureRandom = new SecureRandom();
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        keyPairGenerator.initialize(sm2Spec);
        keyPairGenerator.initialize(sm2Spec, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String[] result = {
                new String(Base64.getEncoder().encode(publicKey.getEncoded()))
                , new String(Base64.getEncoder().encode(privateKey.getEncoded()))
        };
        return result;
    }
    /**
     * 将Base64转码的公钥串，转化为公钥对象
     *
     * @param publicKey
     * @return
     */
    public static PublicKey createPublicKey(String publicKey) {
        PublicKey publickey = null;
        try{
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            publickey = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publickey;
    }

    /**
     * 将Base64转码的私钥串，转化为私钥对象
     *
     * @param privateKey
     * @return
     */
    public static PrivateKey createPrivateKey(String privateKey) {
        PrivateKey publickey = null;
        try{
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            publickey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publickey;
    }

    /**
     * 根据参数 parmA 和 parmB 生成密钥对
     */
    public static String[] KeyExchange(String parmA, String parmB) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        SecureRandom secureRandom = new SecureRandom((parmA + parmB).getBytes());
        keyPairGenerator.initialize(sm2Spec, secureRandom);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String[] result = {
                Base64.getEncoder().encodeToString(publicKey.getEncoded()),
                Base64.getEncoder().encodeToString(privateKey.getEncoded())
        };
        return result;
    }



    /**
     * 使用公钥对原始数据进行SM2加密
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey) {
        try {
            ECPublicKeyParameters ecPublicKeyParameters = getECPublicKeyParameters(publicKey);
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用私钥对加密数据进行SM2解密
     */
    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) {
        try {
            ECPrivateKeyParameters ecPrivateKeyParameters = getECPrivateKeyParameters(privateKey);
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(false, ecPrivateKeyParameters);
            return sm2Engine.processBlock(encryptedData, 0, encryptedData.length);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用私钥对数据进行SM2签名
     */
    public static byte[] signByPrivateKey(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用公钥对数据进行SM2验签
     */
    public static boolean verifyByPublicKey(byte[] data, PublicKey publicKey, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), BouncyCastleProvider.PROVIDER_NAME);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 将公钥转换为ECPublicKeyParameters对象
     */
    private static ECPublicKeyParameters getECPublicKeyParameters(PublicKey publicKey) {
        if (publicKey instanceof BCECPublicKey) {
            BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec ecParameterSpec = bcecPublicKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
            return new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);
        }
        throw new IllegalArgumentException("Invalid public key type.");
    }

    /**
     * 将私钥转换为ECPrivateKeyParameters对象
     */
    private static ECPrivateKeyParameters getECPrivateKeyParameters(PrivateKey privateKey) {
        if (privateKey instanceof BCECPrivateKey) {
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
            ECParameterSpec ecParameterSpec = bcecPrivateKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
            return new ECPrivateKeyParameters(bcecPrivateKey.getD(), ecDomainParameters);
        }
        throw new IllegalArgumentException("Invalid private key type.");
    }

    public static PublicKey CPublicKey(String publicKey) throws Exception {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PrivateKey CPrivateKey(String privateKey) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }



    public static void main(String[] args) throws Exception {

        String test = "This is a 测试！";
        String parmA = "Alice";
        String parmB = "Bob";

        String[] keys = SM2Utils.KeyExchange(parmA, parmB);

        /** SM2 加密 **/

        System.out.println("待加密数据：" + test);
        System.out.println("\nSM2 加密公钥：" + keys[0]);

        PublicKey publicKey = createPublicKey(keys[0]);

        System.out.println("\nSM2 解密私钥：" + keys[1]);

        PrivateKey privateKey = createPrivateKey(keys[1]);

        byte[] encrypt = SM2Utils.encrypt(test.getBytes(), publicKey);
        String encryptBase64Str = Base64.getEncoder().encodeToString(encrypt);
        System.out.println("\nSM2 加密结果：" + encryptBase64Str);

        byte[] decrypt = SM2Utils.decrypt(encrypt, privateKey);

        if (decrypt != null) {
            System.out.println("\nSM2 解密结果：" + new String(decrypt));
        }

        /** SM2 签名 **/

        System.out.println("\n\n\nSM2 待签名数据：" + test);
        System.out.println("\nSM2 验证公钥：" + keys[0]);

        publicKey = createPublicKey(keys[0]);

        System.out.println("\nSM2 签名私钥：" + keys[1]);

        privateKey = createPrivateKey(keys[1]);

        byte[] sign = SM2Utils.signByPrivateKey(test.getBytes(), privateKey);
        System.out.println("\nSM2 签名结果：" + Base64.getEncoder().encodeToString(sign));

        boolean b = SM2Utils.verifyByPublicKey(test.getBytes(), publicKey, sign);
        System.out.println("\nSM2 验证结果：" + b);

    }

}
