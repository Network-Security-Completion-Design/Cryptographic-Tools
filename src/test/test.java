package test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import AlgorithmUtils.*;
import static AlgorithmUtils.ECCUtils.*;
import static com.sun.deploy.util.Base64Wrapper.encodeToString;
import static org.apache.commons.codec.binary.Base64.*;
import static AlgorithmUtils.AESUtils.generateAESKey;
import static AlgorithmUtils.BlowFishUtils.decodingByBase64;
import static AlgorithmUtils.BlowFishUtils.encodingToBase64;
import static AlgorithmUtils.DESUtils.generateDESKey;
import static AlgorithmUtils.HMACUtils.*;
import static AlgorithmUtils.RC4Utils.decryRC4;
import static AlgorithmUtils.RC4Utils.encryRC4String;
import static AlgorithmUtils.RSAUtils.*;
import static AlgorithmUtils.SHAUtils.*;
import static AlgorithmUtils.SM2Utils.createPrivateKey;
import static AlgorithmUtils.SM2Utils.createPublicKey;
import static AlgorithmUtils.SM4Utils.*;
import static AlgorithmUtils.TripleDESUtils.genkey;
import static AlgorithmUtils.utils.StringByteHexUtils.bytesToHex;

public class test {

    public static void main(String[] args) throws Exception {

        String test = "This is a 测试！";

       /*
          RC4 加密测试Test
          **/
        System.out.println("———————————————————— RC4 加密测试 ————————————————————");

        RC4Enc(test);



        /*
          BlowFish 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— BlowFish 加密测试 ————————————————————");

        BFEnc(test);



        /*
        IDEA 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— IDEA 加密测试 ————————————————————");

        SecretKey IDEAKey = IDEAUtils.generateKey();

        IDEAEnc(test, IDEAKey);


       /*
          DES 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— DES 加密测试 ————————————————————");

        String DESKey = String.valueOf(generateDESKey());

        DESEnc(test, DESKey);



       /*
          TripleDES 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— Triple DES 加密测试 ————————————————————");

        SecretKey TDESKey = genkey();

        TDESEnc(test, TDESKey);



        /*
          AES 密钥交换测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— AES 加密测试 ————————————————————");

        String AESKey = String.valueOf(generateAESKey(256));

        AESEnc(test, AESKey);



        /*
          MD5 哈希测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— MD5 哈希测试 ————————————————————");

        MD5(test);



        /*
          SHA 哈希测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SHA 哈希测试 ————————————————————");

        SHA(test);



        /*
          HMAC 哈希测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— HMAC 哈希测试 ————————————————————");

        HMAC(test, new SecureRandom().toString());



        /*
          DSA 签名测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— DSA 签名测试 ————————————————————");

        KeyPair DSAkeyPair = DSAUtils.initKey();

        DSASign(test, DSAkeyPair);



        /*
          RSA 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— RSA 加密测试 ————————————————————");

        KeyPair RSAkeyPair = generateKeyPair(2048);

        RSAEnc(test, RSAkeyPair);



        /*
          RSA 签名测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— RSA 签名测试 ————————————————————");

        RSASign(test, RSAkeyPair);



        /*
          ECC 加密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— ECC 加密测试 ————————————————————");

        KeyPair keypair = ECCUtils.initKey(256, "EC");

        ECCEnc(test, keypair);



        /*
          ECC 签名测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— ECC 签名测试 ————————————————————");

        ECCSign(test, keypair);



        /*
          SM2 密钥交换测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SM2 密钥交换测试 ————————————————————");

        String parmA = "Alice";
        String parmB = "Bob";

        System.out.println("密钥参数 A: " + parmA);
        System.out.println("\n密钥参数 B: " + parmB);

        String[] keys = SM2Utils.KeyExchange(parmA, parmB);

        System.out.println("\n共享密钥 公钥部分: " + keys[0]);
        System.out.println("\n共享密钥 私钥部分: " + keys[1]);



        /*
          SM2 加解密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SM2 加密测试 ————————————————————");

        SM2Enc(test, keys);



        /*
          SM2 签名测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SM2 签名测试 ————————————————————");

        SM2Sign(test, keys);



        /*
          SM3 哈希测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SM3 哈希测试 ————————————————————");

        SM3hash(test);



        /*
          SM4 加解密测试
          **/
        System.out.println("\n\n\n");
        System.out.println("———————————————————— SM4 加密测试 ————————————————————");

        SM4Enc(test, parmA, parmB);
    }



    public static void RC4Enc(String test) throws UnsupportedEncodingException {

        SecureRandom secureRandom = new SecureRandom();

        String key = Base64.getEncoder().encodeToString(Objects.requireNonNull(RC4Utils.initKey(secureRandom.toString())));

        System.out.println("RC4 加解密明文: " + test);
        System.out.println("\nRC4 加解密密钥: " + key);

        String encryStr = encryRC4String(test, key,"UTF-8");
        System.out.println("\nRC4 密文: "+ encryStr);

        String decryStr = decryRC4(encryStr, key, "UTF-8");
        System.out.println("\nRC4 解密明文: "+ decryStr);
    }



    public static void BFEnc(String test) {

        SecureRandom secureRandom = new SecureRandom();

        String key = String.valueOf(secureRandom);

        System.out.println("Blowfish 加解密明文: " + test);

        System.out.println("\nBlowfish 加解密密钥: " + Base64.getEncoder().encodeToString(key.getBytes()));

        String encrypt = encodingToBase64(key, test);
        System.out.println("\nBlowfish 密文: " + encrypt);

        String decodingByBase64 = decodingByBase64(key, encrypt);
        System.out.println("\nBlowfish 解密明文: " + decodingByBase64);
    }



    public static void IDEAEnc(String test, SecretKey key){
        try {

            System.out.println("IDEA 加解密明文: " + test);

            byte[] plainBytes = test.getBytes();

            System.out.println("\nIDEA 加解密密钥: " + Base64.getEncoder().encodeToString(key.getEncoded()));

            byte[] encryptedBytes = IDEAUtils.encrypt(plainBytes, key);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            System.out.println("\nIDEA 密文: " + encryptedText);

            byte[] decryptedBytes = IDEAUtils.decrypt(Base64.getDecoder().decode(encryptedText), key);
            String decryptedText = new String(decryptedBytes);

            System.out.println("\nIDEA 解密密文: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    public static void DESEnc(String test,  String key) throws Exception {

        byte[] encriptMsg = DESUtils.encrypt(test, key);
        System.out.println("DES 加解密明文: " + test);
        System.out.println("\nDES 加解密密钥: " + encodeBase64String(key.getBytes()));

        String encoded = encodeBase64String(encriptMsg);
        System.out.println("\nDES 密文: " + encoded);

        byte[] decoded = decodeBase64(encoded);

        byte[] _decryResult = DESUtils.decrypt(decoded, key);
        System.out.println("\nDES 解密明文: " + new String(_decryResult));
    }



    public static void TDESEnc(String test, SecretKey secretKey) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        System.out.println("Triple DES 加解密明文: " + test);

        System.out.println("\nTriple DES 加解密密钥: " + encodeBase64String(secretKey.toString().getBytes()));

        byte[] encrypted = TripleDESUtils.encrypt(test, secretKey);

        System.out.println("\nTriple DES 密文: " + encodeToString(encrypted));

        String decrypted = TripleDESUtils.decrypt(encrypted, secretKey);

        System.out.println("\nTriple DES 解密明文: " + decrypted);

    }



    public static void AESEnc(String test, String key){
        try {

            System.out.println("AES 加解密明文: " + test);

            System.out.println("\nAES 加解密密钥: " + encodeBase64String(key.getBytes()));

            String cipherText = AESUtils.ecodes(test, key, 256);
            System.out.println("\nAES 密文: " + cipherText);

            String clearText = AESUtils.decodes(cipherText, key, 256);
            System.out.println("\nAES 解密明文：" + clearText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    public static void MD5(String test){

        System.out.println("MD5 哈希明文: " + test);

        System.out.println("\nMD5加密后(密文长度16位): " + MD5Utils.MD5(test, 16));
        System.out.println("\nMD5加密后(密文长度32位): " + MD5Utils.MD5(test, 32));
    }



    public static void SHA(String test){

        System.out.println("SHA 哈希明文: " + test);

        System.out.println("\nSHA-1: " + sha1(test));
        System.out.println("\nSHA-256: " + sha256(test));
        System.out.println("\nSHA-512: " + sha512(test));
    }



    public static void HMAC(String test, String key){
        try {

            System.out.println("HMAC 哈希明文: " + test);

            String hmac = bytesToHex(HMACMD5(key, test));
            System.out.println("\nMD5: " + hmac);

            hmac = bytesToHex(HMACSHA1(key, test));
            System.out.println("\nSHA1: " + hmac);

            hmac = bytesToHex(HMACSHA256(key, test));
            System.out.println("\nSHA256: " + hmac);

            hmac = bytesToHex(HMACSHA384(key, test));
            System.out.println("\nSHA384: " + hmac);

            hmac = bytesToHex(HMACSHA512(key, test));
            System.out.println("\nSHA512: " + hmac);

            hmac = bytesToHex(HMACSHA3(key, test));
            System.out.println("\nSHA3: " + hmac);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }



    public static void DSASign(String test, KeyPair keyPair) throws Exception {

        byte[] keyPairPrivate = keyPair.getPrivate().getEncoded();
        byte[] keyPairPublic = keyPair.getPublic().getEncoded();

        System.out.println("DSA 签名明文: " + test);

        System.out.println("\nDSA 签名私钥: " + encodeBase64String(keyPairPrivate));
        System.out.println("\nDSA 验证公钥: " + encodeBase64String(keyPairPublic));

        for (DSAUtils.DSASignatureAlgorithm algorithm : DSAUtils.DSASignatureAlgorithm.values()) {

            System.out.println("\n\nDSA 签名算法: " + algorithm.getName());
            byte[] signed = DSAUtils.sign(test.getBytes(), keyPairPrivate, algorithm.getName());

            System.out.println("\nDSA 签名: " + encodeBase64String(signed));
            boolean verify = DSAUtils.verify(test.getBytes(), keyPairPublic, signed, algorithm.getName());
            System.out.println("\nDSA 验签: " + verify);
        }
    }



    public static void RSAEnc(String test, KeyPair keyPair) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        System.out.println("RSA 加密明文信息: " + test);

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("\nRSA 加密公钥: " + encodeBase64String(publicKey.getEncoded()));
        System.out.println("\nRSA 解密私钥: " + encodeBase64String(privateKey.getEncoded()));

        // 数据加密和解密示例
        byte[] encryptedData = RSAUtils.encrypt(test.getBytes(StandardCharsets.UTF_8), publicKey);
        byte[] decryptedData = RSAUtils.decrypt(encryptedData, privateKey);
        System.out.println("\nRSA 密文: " + encodeBase64String(encryptedData));
        System.out.println("\nRSA 解密明文: " + new String(decryptedData, StandardCharsets.UTF_8));
    }



    public static void RSASign(String test, KeyPair keyPair) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        System.out.println("RSA 加解密明文: " + test);

        PublicKey publicKey = keyPair.getPublic();

        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("\nRSA 验证公钥: " + encodeBase64String(publicKey.getEncoded()));
        System.out.println("\nRSA 签名私钥: " + encodeBase64String(privateKey.getEncoded()));

        // 数字签名和验证示例
        byte[] signature = sign(test.getBytes(StandardCharsets.UTF_8), privateKey);
        boolean verified = verify(test.getBytes(StandardCharsets.UTF_8), signature, publicKey);
        System.out.println("\nRSA 签名: " + encodeBase64String(signature));
        System.out.println("\nRSA 验签: " + verified);
    }



    public static void ECCEnc(String test, KeyPair keypair) throws Exception {

        System.out.println("ECC 加解密明文: " + test);

        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String publicKeyBase64 = encodeBase64String(publicKey.getEncoded());
        String privateKeyBase64 = encodeBase64String(privateKey.getEncoded());

        //生成固定公钥私钥
        System.out.println("\nECC 加密公钥: " + publicKeyBase64);
        System.out.println("\nECC 加密私钥: " + privateKeyBase64);

        //加密
        String content = encryptByPublicKey(test, publicKeyBase64);
        System.out.println("\nECC 密文: " + content);

        //解密
        String contentDe = decryptByPrivateKey(content, privateKeyBase64);

        String deStr = new String(decodeBase64(contentDe));
        System.out.println("\nECC 解密明文: " + deStr);
    }



    public static void ECCSign(String test, KeyPair keypair) {
        try {

            System.out.println("ECC 签名明文: " + test);

            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            String publicKeyBase64 = encodeBase64String(publicKey.getEncoded());
            String privateKeyBase64 = encodeBase64String(privateKey.getEncoded());

            List<String> algorithm = new ArrayList<>();
            algorithm.add("SHA256withECDSA");
            algorithm.add("SHA384withECDSA");
            algorithm.add("SHA3-256withECDSA");
            algorithm.add("SHA3-384withECDSA");
            algorithm.add("SHA3-512withECDSA");

            //生成固定公钥私钥
            System.out.println("\nECC 验证公钥: " + publicKeyBase64);
            System.out.println("\nECC 签名私钥: " + privateKeyBase64);

            for (String i : algorithm) {

                System.out.println("\n\nECC 签名算法: " + i);
                //签名
                String sign = Sign(test, privateKeyBase64, i);
                System.out.println("\nECC 签名: " + sign);

                //验签
                boolean Ver = Verify(test, sign, publicKeyBase64, i);
                System.out.println("\nECC 验签: " + Ver);
            }
        } catch (Exception e) {
            System.out.println("\n" + e.getMessage());
        }
    }



    public static void SM2Enc(String test, String[] keys) {

        System.out.println("SM2 加解密明文: " + test);

        System.out.println("\nSM2 加密公钥: " + keys[0]);

        PublicKey publicKey = createPublicKey(keys[0]);

        System.out.println("\nSM2 解密私钥: " + keys[1]);

        PrivateKey privateKey = createPrivateKey(keys[1]);

        byte[] encrypt = SM2Utils.encrypt(test.getBytes(), publicKey);
        String encryptBase64Str = encodeBase64String(encrypt);
        System.out.println("\nSM2 密文: " + encryptBase64Str);

        byte[] decrypt = SM2Utils.decrypt(encrypt, privateKey);

        if (decrypt != null) {
            System.out.println("\nSM2 解密明文: " + new String(decrypt));
        }
    }



    public static void SM2Sign(String test, String[] keys) {

        System.out.println("SM2 签名明文: " + test);

        System.out.println("\nSM2 验证公钥: " + keys[0]);

        PublicKey publicKey = createPublicKey(keys[0]);

        System.out.println("\nSM2 签名私钥: " + keys[1]);

        PrivateKey privateKey = createPrivateKey(keys[1]);

        byte[] sign = SM2Utils.signByPrivateKey(test.getBytes(), privateKey);
        System.out.println("\nSM2 签名: " + encodeBase64String(sign));

        boolean b = SM2Utils.verifyByPublicKey(test.getBytes(), publicKey, sign);
        System.out.println("\nSM2 验签: " + b);
    }



    public static void SM3hash(String test) {

        System.out.println("SM3 哈希明文: " + test);

        String s = SM3Utils.sm3Hex(test.getBytes());
        System.out.println("\nSM3: " + s);
        String s2 = SM3Utils.hmacSm3Hex("hmacSm3Hex".getBytes(), test.getBytes());
        System.out.println("\nSM3: " + s2);
    }



    public static void SM4Enc(String test, String parmA, String parmB) throws Exception {
        byte[] key = KeyExchange(parmA, parmB);
        byte[] iv = SM4Utils.generateKey();

        List<String> algorithm = new ArrayList<>();
        algorithm.add(("SM4/ECB/NOPADDING"));
        algorithm.add(("SM4/ECB/PKCS5PADDING"));
        algorithm.add(("SM4/ECB/ISO10126PADDING"));
        algorithm.add(("SM4/CBC/NOPADDING"));
        algorithm.add(("SM4/CBC/PKCS5PADDING"));
        algorithm.add(("SM4/CBC/ISO10126PADDING"));
        algorithm.add(("SM4/CTR/NOPADDING"));
        algorithm.add(("SM4/CTR/PKCS5PADDING"));
        algorithm.add(("SM4/CTR/ISO10126PADDING"));
        algorithm.add(("SM4/CTS/NOPADDING"));
        algorithm.add(("SM4/CTS/PKCS5PADDING"));
        algorithm.add(("SM4/CTS/ISO10126PADDING"));

        for (String s : algorithm) {
            // SM4加密
            try {
                System.out.println("------------------------------------------------------------");
                System.out.println("\nSM4 加密算法: " + s);
                System.out.println("\nSM4 加解密明文: " + test);
                System.out.println("\nSM4 加解密密钥: " + encodeBase64String(key));
                System.out.println("\nSM4 加密iv: " + encodeBase64String(iv));

                if (Objects.equals(s, "SM4/ECB/NOPADDING") || Objects.equals(s, "SM4/CBC/NOPADDING")){
                    try {

                        byte[] paddedData = padData(test.getBytes(), 16); // 假设块长度为16字节
                        byte[] encrypt = SM4Utils.encrypt(s, key, iv, paddedData);
                        System.out.println("\nSM4 密文: " + encodeBase64String(encrypt));

                        // SM4解密
                        byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
                        byte[] unpaddedData = unpadData(decrypt);
                        System.out.println("\nSM4 解密明文: " + new String(unpaddedData));
                        continue;
                    } catch (Exception e) {
                        System.err.println("\nSM4 解密算法 " + s + "::" + e.getMessage());
                    } finally {
                        System.out.println("------------------------------------------------------------");
//                        TimeUnit.SECONDS.sleep(1);
                    }
                }

                byte[] encrypt = SM4Utils.encrypt(s, key, iv, test.getBytes());
                System.out.println("\nSM4 密文: " + encodeBase64String(encrypt));

                // SM4解密
                byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
                System.out.println("\nSM4 解密明文: " + new String(decrypt));
            } catch (Exception e) {
                if (e instanceof IllegalBlockSizeException) {
                    System.err.println("\nSM4 解密算法 " + s + " 数据需自己手工对齐");
                    System.err.println(e.getMessage());
                } else {
                    System.err.println("\nSM4 解密算法 " + s + "::" + e.getMessage());
                }
            } finally {
                System.out.println("------------------------------------------------------------");
//                TimeUnit.SECONDS.sleep(1);
            }
        }
    }
}
