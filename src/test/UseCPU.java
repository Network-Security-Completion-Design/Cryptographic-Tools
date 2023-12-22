package test;

import AlgorithmUtils.*;
import org.knowm.xchart.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.awt.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
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
import static AlgorithmUtils.ECCUtils.Verify;
import static AlgorithmUtils.HMACUtils.*;
import static AlgorithmUtils.HMACUtils.HMACSHA3;
import static AlgorithmUtils.RC4Utils.decryRC4;
import static AlgorithmUtils.RC4Utils.encryRC4String;
import static AlgorithmUtils.RSAUtils.*;
import static AlgorithmUtils.RSAUtils.generateKeyPair;
import static AlgorithmUtils.SHAUtils.*;
import static AlgorithmUtils.SHAUtils.sha3;
import static AlgorithmUtils.SM2Utils.createPrivateKey;
import static AlgorithmUtils.SM2Utils.createPublicKey;
import static AlgorithmUtils.SM4Utils.*;
import static AlgorithmUtils.TripleDESUtils.genkey;
import static AlgorithmUtils.utils.StringByteHexUtils.bytesToHex;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class UseCPU {

    public static void main(String[] args) throws Exception {

        System.gc();

        // 记录函数调用前的CPU占用率
        double initialCpuUsage = getCpuUsage();
        System.out.println("初始化 CPU: " + initialCpuUsage + "\n");

        String test = "This is a 测试！";
        int numIterations = 10000;

        List<String> Alg = new ArrayList<>();
        List<Double> CPU = new ArrayList<>();

        for (int i = 0; i < numIterations; i++) {

       /*
          RC4 加密测试Test
          **/

            RC4Enc(test);

        }
        double totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("RC4");
        CPU.add(totalCpuUsage);

        System.gc();

        Thread.sleep(3000);



        initialCpuUsage = getCpuUsage();

        for (int i = 0; i < numIterations; i++) {

        /*
          BlowFish 加密测试
          **/

            BFEnc(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("BlowFish");
        CPU.add(totalCpuUsage);

        System.gc();

        Thread.sleep(3000);



        initialCpuUsage = getCpuUsage();

        for (int i = 0; i < numIterations; i++) {

        /*
        IDEA 加密测试
          **/

            SecretKey IDEAKey = IDEAUtils.generateKey();

            IDEAEnc(test, IDEAKey);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("IDEA");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

       /*
          DES 加密测试
          **/

            String DESKey = String.valueOf(generateDESKey());

            DESEnc(test, DESKey);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("DES");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

       /*
          TripleDES 加密测试
          **/

            SecretKey TDESKey = genkey();

            TDESEnc(test, TDESKey);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("Triple DES");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          AES 密钥交换测试
          **/

            String AESKey = String.valueOf(generateAESKey(256));

            AESEnc(test, AESKey);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("AES");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          SM4 加解密测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            SM4Enc(test, parmA, parmB);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SM4");
        CPU.add(totalCpuUsage);


        savecpu(Alg, CPU, "Symmetric Algorithm CPU", 800, 600);



        Alg.clear();
        CPU.clear();



        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {
            /*
          MD5 哈希测试
          **/

            MD5(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("MD5");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            sha1(test);


        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SHA1");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            sha256(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SHA256");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            sha512(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SHA512");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            sha3(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SHA3");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            HMACMD5(new SecureRandom().toString(), test);


        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("HMD5");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            HMACSHA1(new SecureRandom().toString(), test);


        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("HSHA1");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

            HMACSHA256(new SecureRandom().toString(), test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("HSHA256");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();


        for (int i = 0; i < numIterations; i++) {

            HMACSHA3(new SecureRandom().toString(), test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("HSHA3");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          SM3 哈希测试
          **/

            SM3hash(test);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SM3");
        CPU.add(totalCpuUsage);

        savecpu(Alg, CPU, "Hash Algorithm CPU", 800, 600);

        Alg.clear();
        CPU.clear();

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          DSA 签名测试
          **/


            KeyPair DSAkeyPair = DSAUtils.initKey();

            DSASign(test, DSAkeyPair);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("DSA Sign");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          RSA 加密测试
          **/

            KeyPair RSAkeyPair = generateKeyPair(2048);

            RSAEnc(test, RSAkeyPair);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("RSA Enc");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          RSA 签名测试
          **/
            KeyPair RSAkeyPair = generateKeyPair(2048);

            RSASign(test, RSAkeyPair);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("RSA Sign");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          ECC 加密测试
          **/

            KeyPair keypair = ECCUtils.initKey(256, "EC");

            ECCEnc(test, keypair);
        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("ECC Enc");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          ECC 签名测试
          **/
            KeyPair keypair = ECCUtils.initKey(256, "EC");

            ECCSign(test, keypair);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("ECC Sign");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          SM2 加解密测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            String[] keys = SM2Utils.KeyExchange(parmA, parmB);

            SM2Enc(test, keys);

        }
        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SM2 Enc");
        CPU.add(totalCpuUsage);

        System.gc();
        Thread.sleep(3000);

        initialCpuUsage = getCpuUsage();



        for (int i = 0; i < numIterations; i++) {

        /*
          SM2 签名测试
          **/
            String parmA = "Alice";
            String parmB = "Bob";

            String[] keys = SM2Utils.KeyExchange(parmA, parmB);


            SM2Sign(test, keys);
        }

        totalCpuUsage = getCpuUsage() - initialCpuUsage;

        Alg.add("SM2 Sign");
        CPU.add(totalCpuUsage);

        savecpu(Alg, CPU, "Asymmetric Algorithm CPU", 1100, 800);
        
    }



    public static void savecpu(List<String> xData, List<Double> yData, String name, int width, int height) throws IOException {
        // 创建柱状图
        CategoryChart chart = new CategoryChartBuilder()
                .width(width)
                .height(height)
                .title(name)
                .xAxisTitle("Algorithm")
                .yAxisTitle("CPU Rate(%)")
                .build();

        System.out.println(name + ": " + yData + "\n");

        // 添加数据
        chart.addSeries("CPU Rate", xData, yData);

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


    public static double getCpuUsage() {
        OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
        if (osBean instanceof com.sun.management.OperatingSystemMXBean) {
            com.sun.management.OperatingSystemMXBean sunOsBean = (com.sun.management.OperatingSystemMXBean) osBean;
            return sunOsBean.getProcessCpuLoad() * 100.0;
        }
        return 0.0;
    }
}
