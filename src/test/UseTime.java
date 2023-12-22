package test;

import AlgorithmUtils.*;
import org.knowm.xchart.BitmapEncoder;
import org.knowm.xchart.CategoryChart;
import org.knowm.xchart.CategoryChartBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.awt.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import static AlgorithmUtils.AESUtils.generateAESKey;
import static AlgorithmUtils.BlowFishUtils.decodingByBase64;
import static AlgorithmUtils.BlowFishUtils.encodingToBase64;
import static AlgorithmUtils.DESUtils.generateDESKey;
import static AlgorithmUtils.ECCUtils.*;
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
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class UseTime {

    public static void main(String[] args) throws Exception {

        List<String> Alg = new ArrayList<>();
        List<Long> UTime = new ArrayList<>();

        String test = "This is a 测试！";

        int numIterations = 1000;
        long start, end, totaltime = 0;

        for (int i = 0; i < numIterations; i++) {

            System.gc();
       /*
          RC4 加密测试Test
          **/
            totaltime = 0;

            start = System.nanoTime();
            RC4Enc(test);
            end = System.nanoTime();

            totaltime += end - start;
        }
        Alg.add("RC4");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          BlowFish 加密测试
          **/

            start = System.nanoTime();
            BFEnc(test);
            end = System.nanoTime();

            totaltime += end - start;
        }
        Alg.add("BlowFiish");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
        IDEA 加密测试
          **/

            start = System.nanoTime();

            SecretKey IDEAKey = IDEAUtils.generateKey();

            IDEAEnc(test, IDEAKey);

            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("IDEA");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
       /*
          DES 加密测试
          **/

            start = System.nanoTime();
            String DESKey = String.valueOf(generateDESKey());

            DESEnc(test, DESKey);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("DES");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
       /*
          TripleDES 加密测试
          **/

            start = System.nanoTime();
            SecretKey TDESKey = genkey();

            TDESEnc(test, TDESKey);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("Triple DES");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          AES 密钥交换测试
          **/

            start = System.nanoTime();
            String AESKey = String.valueOf(generateAESKey(256));

            AESEnc(test, AESKey);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("AES");
        UTime.add(totaltime);



        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          SM4 加解密测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            start = System.nanoTime();
            SM4Enc(test, parmA, parmB);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SM4");
        UTime.add(totaltime);

        savepicture(Alg, UTime, "Symmetric Algorithm", 800, 600);



        Alg.clear();
        UTime.clear();

        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          MD5 哈希测试
          **/

            start = System.nanoTime();
            MD5(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("MD5");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            sha1(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SHA1");
        UTime.add(totaltime);



        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            sha256(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SHA256");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            sha512(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SHA512");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            sha3(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SHA3");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            HMACMD5(new SecureRandom().toString(), test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("HMD5");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            HMACSHA1(new SecureRandom().toString(), test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("HSHA1");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            HMACSHA256(new SecureRandom().toString(), test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("HSHA256");
        UTime.add(totaltime);



        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;

            start = System.nanoTime();
            HMACSHA3(new SecureRandom().toString(), test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("HSHA3");
        UTime.add(totaltime);



        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          SM3 哈希测试
          **/

            start = System.nanoTime();
            SM3hash(test);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SM3");
        UTime.add(totaltime);

        savepicture(Alg, UTime, "Hash Algorithm", 800, 600);



        Alg.clear();
        UTime.clear();

        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          DSA 签名测试
          **/

            start = System.nanoTime();

            KeyPair DSAkeyPair = DSAUtils.initKey();

            DSASign(test, DSAkeyPair);

            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("DSA Sign");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          RSA 加密测试
          **/

            start = System.nanoTime();
            KeyPair RSAkeyPair = generateKeyPair(2048);

            RSAEnc(test, RSAkeyPair);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("RSA Enc");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          RSA 签名测试
          **/
            KeyPair RSAkeyPair = generateKeyPair(2048);

            start = System.nanoTime();
            RSASign(test, RSAkeyPair);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("RSA Sign");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          ECC 加密测试
          **/

            start = System.nanoTime();
            KeyPair keypair = ECCUtils.initKey(256, "EC");

            ECCEnc(test, keypair);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("ECC Enc");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          ECC 签名测试
          **/
            KeyPair keypair = ECCUtils.initKey(256, "EC");

            start = System.nanoTime();
            ECCSign(test, keypair);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("ECC Sign");
        UTime.add(totaltime);



        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          SM2 加解密测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            String[] keys = SM2Utils.KeyExchange(parmA, parmB);

            start = System.nanoTime();
            SM2Enc(test, keys);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SM2 Enc");
        UTime.add(totaltime);


        for (int i = 0; i < numIterations; i++) {
            System.gc();

            totaltime = 0;
        /*
          SM2 签名测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            String[] keys = SM2Utils.KeyExchange(parmA, parmB);


            start = System.nanoTime();
            SM2Sign(test, keys);
            end = System.nanoTime();

            totaltime += end - start;

        }
        Alg.add("SM2 Sign");
        UTime.add(totaltime);

        savepicture(Alg, UTime, "Asymmetric Algorithm", 1000, 800);
        System.out.println("\n");

        Thread.sleep(3000);

        UseCPU.main(args);

        Thread.sleep(3000);

        UseMemory.main(args);

    }

    public static void savepicture(List<String> xData, List<Long> YD, String name, int width, int height) throws IOException {

        List<Double> yData = new ArrayList<>();
        for (Long aLong : YD) {
            yData.add((double) aLong / 1000000.0);
        }

        System.out.println(name + " Time: " + yData + "\n");

        // 创建柱状图
        CategoryChart chart = new CategoryChartBuilder()
                .width(width)
                .height(height)
                .title(name)
                .xAxisTitle("Algorithm")
                .yAxisTitle("Time(ms)")
                .build();

        // 添加数据
        chart.addSeries("Time", xData, yData);

        chart.getStyler().setPlotMargin(0);
        chart.getStyler().setYAxisDecimalPattern("#.##");

        chart.getStyler().setPlotBackgroundColor(Color.WHITE);
        chart.getStyler().setChartBackgroundColor(Color.WHITE);
        chart.getStyler().setPlotGridLinesVisible(false);

        Color lightBlue = Color.getHSBColor(0.55f, 0.7f, 1.0f);
        chart.getStyler().setSeriesColors(new Color[]{lightBlue});

        // 显示图表
//        new SwingWrapper<>(chart).displayChart();

        BitmapEncoder.saveBitmap(chart, name, BitmapEncoder.BitmapFormat.PNG);

    }


    public static void RC4Enc(String test) throws UnsupportedEncodingException {

        SecureRandom secureRandom = new SecureRandom();

        String key = Base64.getEncoder().encodeToString(Objects.requireNonNull(RC4Utils.initKey(secureRandom.toString())));

        String encryStr = encryRC4String(test, key,"UTF-8");

        String decryStr = decryRC4(encryStr, key, "UTF-8");
    }



    public static void BFEnc(String test) {

        SecureRandom secureRandom = new SecureRandom();

        String key = String.valueOf(secureRandom);

        String encrypt = encodingToBase64(key, test);

        String decodingByBase64 = decodingByBase64(key, encrypt);
    }



    public static void IDEAEnc(String test, SecretKey key){
        try {

            byte[] plainBytes = test.getBytes();

            byte[] encryptedBytes = IDEAUtils.encrypt(plainBytes, key);
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            byte[] decryptedBytes = IDEAUtils.decrypt(Base64.getDecoder().decode(encryptedText), key);
            String decryptedText = new String(decryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    public static void DESEnc(String test,  String key) throws Exception {

        byte[] encriptMsg = DESUtils.encrypt(test, key);

        String encoded = encodeBase64String(encriptMsg);

        byte[] decoded = decodeBase64(encoded);

        byte[] _decryResult = DESUtils.decrypt(decoded, key);
    }



    public static void TDESEnc(String test, SecretKey secretKey) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        byte[] encrypted = TripleDESUtils.encrypt(test, secretKey);

        String decrypted = TripleDESUtils.decrypt(encrypted, secretKey);

    }



    public static void AESEnc(String test, String key){
        try {

            String cipherText = AESUtils.ecodes(test, key, 256);

            String clearText = AESUtils.decodes(cipherText, key, 256);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    public static void MD5(String test){

        String cip = MD5Utils.MD5(test, 16);
        cip = MD5Utils.MD5(test, 32);

    }



    public static void SHA(String test) {

        sha1(test);
        sha256(test);
        sha512(test);
        sha3(test);

    }



    public static void HMAC(String test, String key){
        try {


            String hmac = bytesToHex(HMACMD5(key, test));

            hmac = bytesToHex(HMACSHA1(key, test));

            hmac = bytesToHex(HMACSHA256(key, test));

            hmac = bytesToHex(HMACSHA384(key, test));

            hmac = bytesToHex(HMACSHA512(key, test));

            hmac = bytesToHex(HMACSHA3(key, test));

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }



    public static void DSASign(String test, KeyPair keyPair) throws Exception {

        byte[] keyPairPrivate = keyPair.getPrivate().getEncoded();
        byte[] keyPairPublic = keyPair.getPublic().getEncoded();

        for (DSAUtils.DSASignatureAlgorithm algorithm : DSAUtils.DSASignatureAlgorithm.values()) {

            byte[] signed = DSAUtils.sign(test.getBytes(), keyPairPrivate, algorithm.getName());

            boolean verify = DSAUtils.verify(test.getBytes(), keyPairPublic, signed, algorithm.getName());
        }
    }



    public static void RSAEnc(String test, KeyPair keyPair) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 数据加密和解密示例
        byte[] encryptedData = RSAUtils.encrypt(test.getBytes(StandardCharsets.UTF_8), publicKey);
        byte[] decryptedData = RSAUtils.decrypt(encryptedData, privateKey);
    }



    public static void RSASign(String test, KeyPair keyPair) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {


        PublicKey publicKey = keyPair.getPublic();

        PrivateKey privateKey = keyPair.getPrivate();

        // 数字签名和验证示例
        byte[] signature = sign(test.getBytes(StandardCharsets.UTF_8), privateKey);
        boolean verified = verify(test.getBytes(StandardCharsets.UTF_8), signature, publicKey);
    }



    public static void ECCEnc(String test, KeyPair keypair) throws Exception {

        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String publicKeyBase64 = encodeBase64String(publicKey.getEncoded());
        String privateKeyBase64 = encodeBase64String(privateKey.getEncoded());

        //生成固定公钥私钥

        //加密
        String content = encryptByPublicKey(test, publicKeyBase64);

        //解密
        String contentDe = decryptByPrivateKey(content, privateKeyBase64);

        String deStr = new String(decodeBase64(contentDe));
    }



    public static void ECCSign(String test, KeyPair keypair) {
        try {

            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            String publicKeyBase64 = encodeBase64String(publicKey.getEncoded());
            String privateKeyBase64 = encodeBase64String(privateKey.getEncoded());

            String i = ("SHA256withECDSA");


            //签名
            String sign = Sign(test, privateKeyBase64, i);

            //验签
            boolean Ver = Verify(test, sign, publicKeyBase64, i);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
    }




    public static void SM2Enc(String test, String[] keys) {

        PublicKey publicKey = createPublicKey(keys[0]);

        PrivateKey privateKey = createPrivateKey(keys[1]);

        byte[] encrypt = SM2Utils.encrypt(test.getBytes(), publicKey);
        String encryptBase64Str = encodeBase64String(encrypt);

        byte[] decrypt = SM2Utils.decrypt(encrypt, privateKey);
        String dec = new String(decrypt);

    }



    public static void SM2Sign(String test, String[] keys) {

        PublicKey publicKey = createPublicKey(keys[0]);

        PrivateKey privateKey = createPrivateKey(keys[1]);

        byte[] sign = SM2Utils.signByPrivateKey(test.getBytes(), privateKey);

        boolean b = SM2Utils.verifyByPublicKey(test.getBytes(), publicKey, sign);
    }



    public static void SM3hash(String test) {

        String s = SM3Utils.sm3Hex(test.getBytes());
        String s2 = SM3Utils.hmacSm3Hex("hmacSm3Hex".getBytes(), test.getBytes());
    }



    public static void SM4Enc(String test, String parmA, String parmB) throws Exception {
        byte[] key = KeyExchange(parmA, parmB);
        byte[] iv = SM4Utils.generateKey();


        String s = "SM4/CBC/ISO10126PADDING";


        // SM4加密

        try {

            byte[] paddedData = padData(test.getBytes(), 16); // 假设块长度为16字节
            byte[] encrypt = SM4Utils.encrypt(s, key, iv, paddedData);

            // SM4解密
            byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
            byte[] unpaddedData = unpadData(decrypt);
        } catch (Exception ignored) {
        }


        byte[] encrypt = SM4Utils.encrypt(s, key, iv, test.getBytes());

        try {
            // SM4解密
            byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
        } catch (Exception e) {
            if (e instanceof IllegalBlockSizeException) {
                System.err.println(e.getMessage());
            }

        }
    }
}
