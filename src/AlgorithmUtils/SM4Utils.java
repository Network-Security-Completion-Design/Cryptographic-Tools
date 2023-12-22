package AlgorithmUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.*;

public class SM4Utils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final String ALGORITHM_NAME = "SM4";
    public static final String DEFAULT_KEY = "random_seed";
    // 128-32位16进制；256-64位16进制
    public static final int DEFAULT_KEY_SIZE = 128;


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] KeyExchange(String parmA, String parmB) throws NoSuchAlgorithmException {
        String keyInput = parmA + parmB;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(keyInput.getBytes());
        return Arrays.copyOf(key, DEFAULT_KEY_SIZE / 8);
    }



    public static byte[] generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKey(DEFAULT_KEY, DEFAULT_KEY_SIZE);
    }



    public static byte[] generateKey(String seed) throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKey(seed, DEFAULT_KEY_SIZE);
    }



    public static byte[] generateKey(String seed, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        if (null != seed && !"".equals(seed)) {
            random.setSeed(seed.getBytes());
        }
        kg.init(keySize, random);
        return kg.generateKey().getEncoded();
    }



    public static byte[] padData(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingLength;
        }
        return paddedData;
    }



    public static byte[] unpadData(byte[] data) {
        int paddingLength = data[data.length - 1];
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }



    public static byte[] encrypt(String algorithmName, byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        if (algorithmName.contains("/ECB/")) {
            cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, sm4Key, ivParameterSpec);
        }

        return cipher.doFinal(data);
    }



    /**
     * @description 解密
     */
    public static byte[] decrypt(String algorithmName, byte[] key, byte[] iv, byte[] data) throws Exception {
        return sm4core(algorithmName, Cipher.DECRYPT_MODE, key, iv, data);
    }



    private static byte[] sm4core(String algorithmName, int type, byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        if (algorithmName.contains("/ECB/")) {
            cipher.init(type, sm4Key);
        }
        else {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(type, sm4Key, ivParameterSpec);
            }

        return cipher.doFinal(data);
    }



    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

        String test = "This is a 测试！";

        String parmA = "Alice";
        String parmB = "Bob";

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
                System.out.println("SM4 加密算法： " + s);
                System.out.println("\nSM4 待加密数据： " + test);
                System.out.println("\nSM4 加密key： " + Base64.getEncoder().encodeToString(key));
                System.out.println("\nSM4 加密iv： " + Base64.getEncoder().encodeToString(iv));

                if (Objects.equals(s, "SM4/ECB/NOPADDING") || Objects.equals(s, "SM4/CBC/NOPADDING")){
                    try {

                        byte[] paddedData = padData(test.getBytes(), 16); // 假设块长度为16字节
                        byte[] encrypt = SM4Utils.encrypt(s, key, iv, paddedData);
                        System.out.println("\nSM4 加密数据密文： " + Base64.getEncoder().encodeToString(encrypt));

                        // SM4解密
                        byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
                        byte[] unpaddedData = unpadData(decrypt);
                        System.out.println("\nSM4 解密数据： " + new String(unpaddedData));
                        continue;
                    } catch (Exception e) {
                        System.err.println("\nSM4 解密算法 " + s + "::" + e.getMessage());
                    } finally {
                        System.out.println("------------------------------------------------------------");
//                        TimeUnit.SECONDS.sleep(1);
                    }
                }

                byte[] encrypt = SM4Utils.encrypt(s, key, iv, test.getBytes());
                System.out.println("\nSM4 加密数据密文： " + Base64.getEncoder().encodeToString(encrypt));

                // SM4解密
                byte[] decrypt = SM4Utils.decrypt(s, key, iv, encrypt);
                System.out.println("\nSM4 解密数据： " + new String(decrypt));
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
