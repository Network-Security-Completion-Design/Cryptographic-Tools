package app.controller;

import AlgorithmUtils.*;
import AlgorithmUtils.utils.StringByteHexUtils;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import javafx.scene.image.Image;
import javafx.scene.layout.AnchorPane;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javafx.scene.image.ImageView;
import static AlgorithmUtils.AESUtils.*;

public class Controller implements Initializable {
    @FXML
    AnchorPane dcjm;
    @FXML
    AnchorPane gkjm;
    @FXML
    AnchorPane slsf;
    @FXML
    AnchorPane szqm;

    @FXML
    TextArea des1_1;
    @FXML
    TextArea des1_2;
    @FXML
    TextArea des1_3;
    @FXML
    TextArea des1_4;
    @FXML
    TextArea des1_5;
    @FXML
    TextArea des1_6;
    @FXML
    TextArea des1_7;
    @FXML
    TextArea des1_8;
    @FXML
    TextArea des1_9;
    @FXML
    TextArea des1_10;
    @FXML
    TextArea des1_11;
    @FXML
    TextArea des1_12;
    @FXML
    TextArea des1_13;
    @FXML
    TextArea des1_14;
    @FXML
    TextArea des1_15;
    @FXML
    TextArea des1_16;
    @FXML
    TextArea des1_17;
    @FXML
    TextArea des1_18;
    @FXML
    TextArea des1_19;
    @FXML
    TextArea des1_20;
    @FXML
    TextArea des1_21;
    @FXML
    TextArea des1_22;
    @FXML
    TextArea des1_23;
    @FXML
    TextArea des1_24;
    @FXML
    TextArea des1_25;
    @FXML
    TextArea des1_26;
    @FXML
    TextArea des1_27;
    @FXML
    TextArea des1_28;
    @FXML
    TextArea des1_29;
    @FXML
    TextArea des1_30;
    @FXML
    TextArea des1_31;
    @FXML
    TextArea des1_32;
    @FXML
    TextArea des1_33;
    @FXML
    TextArea des1_34;
    @FXML
    TextArea des1_35;
    @FXML
    TextArea des1_36;
    @FXML
    TextArea des1_37;
    @FXML
    TextArea des1_38;
    @FXML
    TextArea des1_39;
    @FXML
    TextArea des1_40;
    @FXML
    TextArea des1_41;
    @FXML
    TextArea des1_42;



    @FXML
    TextArea des2_1;
    @FXML
    TextArea des2_2;
    @FXML
    TextArea des2_3;
    @FXML
    TextArea des2_4;
    @FXML
    TextArea des2_6;
    @FXML
    TextArea des2_7;
    @FXML
    TextArea des2_8;
    @FXML
    TextArea des2_9;
    @FXML
    TextArea des2_10;
    @FXML
    TextArea des2_11;
    @FXML
    TextArea des2_12;

    @FXML
    TextArea des2_14;
    @FXML
    TextArea des2_15;
    @FXML
    TextArea des2_16;
    @FXML
    TextArea des2_17;



    @FXML
    TextArea des3_1;
    @FXML
    TextArea des3_2;
    @FXML
    CheckBox toUpper1;
    @FXML
    TextArea des3_3;
    @FXML
    TextArea des3_4;
    @FXML
    CheckBox toUpper2;
    @FXML
    TextArea des3_5;
    @FXML
    TextArea des3_6;
    @FXML
    CheckBox toUpper3;
    @FXML
    TextArea des3_7;
    @FXML
    TextArea des3_8;
    @FXML
    CheckBox toUpper4;
    @FXML
    TextArea des3_9;
    @FXML
    TextArea des3_10;
    @FXML
    CheckBox toUpper5;
    @FXML
    TextArea des3_11;
    @FXML
    TextArea des3_12;
    @FXML
    TextArea des3_13;
    @FXML
    CheckBox toUpper6;
    @FXML
    TextArea des3_14;
    @FXML
    TextArea des3_15;
    @FXML
    TextArea des3_16;
    @FXML
    CheckBox toUpper7;
    @FXML
    TextArea des3_17;
    @FXML
    TextArea des3_18;
    @FXML
    TextArea des3_19;
    @FXML
    CheckBox toUpper8;
    @FXML
    TextArea des3_20;
    @FXML
    TextArea des3_21;
    @FXML
    TextArea des3_22;
    @FXML
    CheckBox toUpper9;

    @FXML
    TextArea des4_1;
    @FXML
    TextArea des4_2;
    @FXML
    TextArea des4_3;
    @FXML
    TextArea des4_4;
    @FXML
    TextArea des4_6;
    @FXML
    TextArea des4_7;
    @FXML
    TextArea des4_8;
    @FXML
    TextArea des4_9;
    @FXML
    TextArea des4_10;
    @FXML
    TextArea des4_11;
    @FXML
    TextArea des4_12;
    @FXML
    TextArea des4_14;
    @FXML
    TextArea des4_15;
    @FXML
    TextArea des4_16;
    @FXML
    TextArea des4_17;


    @FXML
    private ImageView iconImageView;



    // 按钮-界面切换
    public void buttonDCJM() {
        dcjm.setVisible(true);
        gkjm.setVisible(false);
        slsf.setVisible(false);
        szqm.setVisible(false);
    }
    public void buttonGKJM() {
        gkjm.setVisible(true);
        dcjm.setVisible(false);
        slsf.setVisible(false);
        szqm.setVisible(false);
    }
    public void buttonSL() {
        slsf.setVisible(true);
        dcjm.setVisible(false);
        gkjm.setVisible(false);
        szqm.setVisible(false);
    }
    public void buttonSZQM() {
        szqm.setVisible(true);
        slsf.setVisible(false);
        dcjm.setVisible(false);
        gkjm.setVisible(false);
    }




    /** 对称加密 **/
    public void desEncrypt() throws NoSuchAlgorithmException {
        String key = des1_1.getText();
        String clear_pwd = des1_2.getText();

        if (key.isEmpty()) {
            key = Base64.getEncoder().encodeToString((new SecureRandom()).toString().getBytes());
        }

        String DESkey = String.valueOf(GenKey(key));

        des1_1.setText(Base64.getEncoder().encodeToString(DESkey.getBytes()));

        String cip = Base64.getEncoder().encodeToString(Objects.requireNonNull(DESUtils.encrypt(clear_pwd, DESkey)));

        des1_3.setText(cip);
    }
    public void desDecrypt() {
        String key = des1_1.getText();
        String secret_pwd = des1_3.getText();

        String DESKey = null;
        try {
            DESKey = new String(Base64.getDecoder().decode(key.getBytes()));
            des1_4.setText(key);
        } catch (Exception e) {
            des1_4.setText("密钥错误，请检查密钥信息是否被修改！");
        }

        des1_5.setText(secret_pwd);

        try {
            if (DESKey != null) {
                des1_6.setText(new String(DESUtils.decrypt(Base64.getDecoder().decode(secret_pwd), DESKey)));
            }
            else {
                des1_6.setText("解密失败，请检查密钥和密文是否配套！");
            }
        } catch (Exception e) {
            des1_6.setText("解密失败，请检查密钥和密文是否配套！");
        }

    }



    public void TdesEncrypt() throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        String seed = des1_25.getText();
        String clear_pwd = des1_26.getText();

        SecretKey key;

        if (seed.isEmpty()) {
            seed = String.valueOf(new SecureRandom());
        }
        key = TripleDESUtils.GenKey(seed);

        des1_25.setText(Base64.getEncoder().encodeToString(seed.getBytes()));

        des1_27.setText(Base64.getEncoder().encodeToString(TripleDESUtils.encrypt(clear_pwd, key)));
    }
    public void TdesDecrypt() {
        String seed = des1_25.getText();
        String secret_pwd = des1_27.getText();

        SecretKey key = null;

        try {
            key = TripleDESUtils.GenKey(new String(Base64.getDecoder().decode(seed)));
            des1_28.setText(seed);
        } catch (Exception e) {
            des1_28.setText("密钥错误，请检查密钥信息是否被修改！");
        }

        des1_29.setText(secret_pwd);

        try {
            des1_30.setText(TripleDESUtils.decrypt(Base64.getDecoder().decode(secret_pwd), key));
        } catch (Exception e) {
            des1_30.setText("解密失败，请检查密钥和密文是否配套！");
        }
    }



    public void aesEncrypt() throws Exception {
        String seed = des1_7.getText();
        String clear_pwd = des1_8.getText();

        String key;

        if (seed.isEmpty()) {
            seed = String.valueOf(AESUtils.GenKey(String.valueOf(new SecureRandom())));
        }
        key = String.valueOf(AESUtils.GenKey(seed));

        des1_7.setText(Base64.getEncoder().encodeToString(key.getBytes()));

        des1_9.setText(AESUtils.ecodes(clear_pwd, key, 256));
    }
    public void aesDecrypt() {
        String seed = des1_7.getText();
        String secret_pwd = des1_9.getText();

        String key = null;
        try {
            key = new String(Base64.getDecoder().decode(seed));
            des1_10.setText(seed);
        } catch (Exception e) {
            des1_10.setText("密钥错误，请检查密钥信息是否被修改！");
        }

        des1_11.setText(secret_pwd);

        try {
            des1_12.setText(AESUtils.Decode(secret_pwd, key, 256));
        } catch (Exception e) {
            des1_12.setText("解密失败，请检查密钥和密文是否配套！");
        }
    }




    public void BFEncrypt(){
        String key = des1_13.getText();
        String clear_pwd = des1_14.getText();

        if (key.isEmpty()) {
            key  = String.valueOf(new SecureRandom());
        }

        key = SHAUtils.sha1(key);

        des1_13.setText(Base64.getEncoder().encodeToString(key.getBytes()));

        des1_15.setText(BlowFishUtils.encodingToBase64(key, clear_pwd));
    }
    public void BFDecrypt() {
        String key = des1_13.getText();
        String secret_pwd = des1_15.getText();

        des1_16.setText(key);
        des1_17.setText(secret_pwd);

        try {
            String result = BlowFishUtils.DecodingByBase64(new String(Base64.getDecoder().decode(key)), secret_pwd);

            if (StringByteHexUtils.isValidDecryptionResult(result)) {
                des1_18.setText(result);
            }
            else {
                des1_18.setText("解密失败，请检查密钥和密文是否配套！");
            }

        } catch (Exception e) {
            des1_18.setText("解密失败，请检查密钥和密文是否配套！");
        }
    }



    public void RC4Encrypt() throws UnsupportedEncodingException {
        String key = des1_19.getText();
        String clear_pwd = des1_20.getText();

        if (key.isEmpty()){
            SecureRandom seed = new SecureRandom();
            key = Arrays.toString(RC4Utils.initKey(String.valueOf(seed)));
        }
        else {
            key = Arrays.toString(RC4Utils.initKey(key));
        }

        des1_19.setText(Base64.getEncoder().encodeToString(key.getBytes()));
        des1_21.setText(Base64.getEncoder().encodeToString(RC4Utils.encryRC4String(clear_pwd, key, "UTF-8").getBytes()));
    }
    public void RC4Decrypt() {
        String key = des1_19.getText();
        String secret_pwd = des1_21.getText();

        des1_22.setText(key);
        des1_23.setText(secret_pwd);

        try {
            String result = RC4Utils.decryRC4(new String(Base64.getDecoder().decode(secret_pwd)), new String(Base64.getDecoder().decode(key)), "UTF-8");

            if (StringByteHexUtils.isValidDecryptionResult(result)){
                des1_24.setText(result);
            }
            else {
                des1_24.setText("解密失败，请检查密钥和密文是否配套！");
            }

        } catch (Exception e) {
            des1_24.setText("解密失败，请检查密钥和密文是否配套！");
        }

    }



    public void IDEAEncrypt() throws Exception {
        String seed = des1_31.getText();
        String clear_pwd = des1_32.getText();

        SecretKey key;
        if (seed.isEmpty()) {
            key = IDEAUtils.generateKey();
        } else {
            key = IDEAUtils.GenKey(seed);
        }

        des1_31.setText(Base64.getEncoder().encodeToString(key.getEncoded()));
        des1_33.setText(Base64.getEncoder().encodeToString(IDEAUtils.encrypt(clear_pwd.getBytes(), key)));
    }

    public void IDEADecrypt() {
        String seed = des1_31.getText();
        String secret_pwd = des1_33.getText();
        SecretKey key = null;
        try {
            byte[] decodedKeyBytes = Base64.getDecoder().decode(seed);
            key = new SecretKeySpec(decodedKeyBytes, "IDEA");
            des1_34.setText(seed);
        }
        catch (Exception e) {
            des1_34.setText("密钥错误，请检查密钥信息是否被修改！");
        }


        des1_35.setText(secret_pwd);

        try {
            byte[] decodedPwdBytes = Base64.getDecoder().decode(secret_pwd);

            String result = new String(IDEAUtils.decrypt(decodedPwdBytes, key));

            if (StringByteHexUtils.isValidDecryptionResult(result)) {
                des1_36.setText(result);
            } else {
                des1_36.setText("解密失败，请检查密钥和密文是否配套！");
            }
        } catch (Exception e) {
            des1_36.setText("解密失败，请检查密钥和密文是否配套！");
        }
    }




    public void SM4Encrypt() throws Exception {
        String seed = des1_37.getText();
        String clear_pwd = des1_38.getText();

        byte[] key;

        if (seed.isEmpty()) {
            seed = Base64.getEncoder().encodeToString(new SecureRandom().toString().getBytes());
        }
        key = SM4Utils.generateKey(seed);

        des1_37.setText(Base64.getEncoder().encodeToString(key));

        byte[] iv = Arrays.copyOf(key, 16);

        des1_39.setText(Base64.getEncoder().encodeToString(SM4Utils.encrypt("SM4/CBC/ISO10126PADDING", key, iv, clear_pwd.getBytes())));
    }
    public void SM4Decrypt() {
        String seed = des1_37.getText();
        String secret_pwd = des1_39.getText();

        byte[] key = new byte[0], iv = new byte[0];
        try {
            key = Base64.getDecoder().decode(seed);

            iv = Arrays.copyOf(key, 16);

            des1_40.setText(seed);

        }
        catch (Exception e) {
            des1_40.setText("密钥错误，请检查密钥信息是否被修改！");
        }

        des1_41.setText(secret_pwd);

        try {
            des1_42.setText(new String(SM4Utils.decrypt("SM4/CBC/ISO10126PADDING", key, iv, Base64.getDecoder().decode(secret_pwd))));
        }
        catch (Exception e) {
            des1_42.setText("解密失败，请检查密钥和密文是否配套！");
        }
    }





    /** 非对称加密 **/
    public void RSAGenKey() throws NoSuchAlgorithmException {
        KeyPair key = RSAUtils.generateKeyPair(2048);
        des2_1.setText(org.apache.commons.codec.binary.Base64.encodeBase64String(key.getPublic().getEncoded())); // 公钥
        des2_2.setText(org.apache.commons.codec.binary.Base64.encodeBase64String(key.getPrivate().getEncoded())); // 私钥
    }
    public void rsaEncrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        String publicKeyStr = des2_1.getText();
        PublicKey publicKey;
        try {
            byte[] publicKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        }
        catch (Exception e) {
            des2_4.setText("公钥信息被篡改，无法正常加密！");
            return;
        }
        
        String clear_pwd = des2_3.getText();

        des2_4.setText(Base64.getEncoder().encodeToString(RSAUtils.encrypt(clear_pwd.getBytes(), publicKey)));

    }
    public void rsaDecrypt() throws Exception {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey;
        try {
            String privateKeyStr = des2_2.getText();
            byte[] privateKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(privateKeyStr);
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        }
        catch (Exception e) {
            des2_6.setText("私钥信息被篡改，无法正常解密！");
            return;
        }

        try {
            des2_6.setText(new String(RSAUtils.decrypt(Base64.getDecoder().decode(des2_4.getText()), privateKey)));
        }
        catch (Exception e) {
            des2_6.setText("解密失败，请检查公私钥对以及密文是否配套！");
        }
    }



    public void ECCKeyPair() throws Exception {

        KeyPair keypair = ECCUtils.initKey(256, "EC");

        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String publicKeyBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(publicKey.getEncoded());
        String privateKeyBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(privateKey.getEncoded());

        des2_7.setText(publicKeyBase64);
        des2_8.setText(privateKeyBase64);
    }
    public void eccEncrypt() {
        String clear_pwd = des2_9.getText();
        String publicKeyBase64 = des2_7.getText();

        try {
            des2_10.setText(ECCUtils.encryptByPublicKey(clear_pwd, publicKeyBase64));
        }
        catch (Exception e) {
            des2_10.setText("公钥信息被篡改，无法正常加密！");
        }
    }
    public void eccDecrypt() {
        String secret_pwd = des2_10.getText();
        String privateKeyBase64 = des2_8.getText();

        try {
            des2_11.setText(ECCUtils.Decrypt(secret_pwd, privateKeyBase64));
        }
        catch (Exception e) {
            des2_11.setText("解密失败，请检查公私钥对以及密文是否配套！");
        }
    }



    public void SM2KeyPair() throws Exception {

        String parmA =  new SecureRandom().toString();
        String parmB =  new SecureRandom().toString();

        String[] keys = SM2Utils.KeyExchange(parmA, parmB);

        des2_12.setText(keys[0]);
        des2_14.setText(keys[1]);
    }
    public void SM2Encrypt() {
        String clear_pwd = des2_15.getText();
        String key = des2_12.getText();

        PublicKey publicKey;
        try {
            publicKey = SM2Utils.CPublicKey(key);
        }
        catch (Exception e) {
            des2_16.setText("公钥信息被篡改，无法正常加密！");
            return;
        }

        byte[] cipherTxt= SM2Utils.encrypt(clear_pwd.getBytes(), publicKey);
        if (cipherTxt != null) {
            des2_16.setText(Base64.getEncoder().encodeToString(cipherTxt));
        }
    }
    public void SM2Decrypt() {
        String secret_pwd = des2_16.getText();
        String key = des2_14.getText();

        PrivateKey privateKey;
        try {
            privateKey = SM2Utils.CPrivateKey(key);
        }
        catch (Exception e) {
            des2_17.setText("私钥信息被篡改，无法正常解密！");
            return;
        }

        try {
            byte[] clearTxt = SM2Utils.decrypt(Base64.getDecoder().decode(secret_pwd), privateKey);

            if (clearTxt != null) {
                des2_17.setText(new String(clearTxt));
            }
        }
        catch (Exception e) {
            des2_17.setText("解密失败，请检查公私钥对以及密文是否配套！");
        }
    }





    /** 散列算法 **/
    public void MD5_hash() {
        String clear_pwd = des3_1.getText();
        String secret_pwd = MD5Utils.MD5(clear_pwd, 32);
        if (toUpper1.isSelected()) {
            if (secret_pwd != null) {
                des3_2.setText(secret_pwd.toUpperCase());
            }
        } else {
            if (secret_pwd != null) {
                des3_2.setText(secret_pwd.toLowerCase());
            }
        }
    }



    public void SHA1_hash() {
        String clear_pwd = des3_3.getText();
        String secret_pwd = SHAUtils.sha1(clear_pwd);

        if (toUpper2.isSelected()) {
            des3_4.setText(secret_pwd.toUpperCase());
        } else {
            des3_4.setText(secret_pwd.toLowerCase());
        }
    }

    public void SHA256_hash(){
        String clear_pwd = des3_5.getText();
        String secret_pwd = SHAUtils.sha256(clear_pwd);

        if (toUpper3.isSelected()) {
            des3_6.setText(secret_pwd.toUpperCase());
        } else {
            des3_6.setText(secret_pwd.toLowerCase());
        }
    }

    public void SHA3_hash() {
        String clear_pwd = des3_7.getText();
        String secret_pwd = SHAUtils.sha3(clear_pwd);
        if (toUpper4.isSelected()) {
            if (secret_pwd != null) {
                des3_8.setText(secret_pwd.toUpperCase());
            }
        } else {
            if (secret_pwd != null) {
                des3_8.setText(secret_pwd.toLowerCase());
            }
        }
    }

    public void HMAC_MD5() throws NoSuchAlgorithmException, InvalidKeyException {
        String seed = des3_9.getText();
        String clear_pwd = des3_10.getText();

        String key;

        if (seed.isEmpty()) {
            seed = (new SecureRandom()).toString();
        }

        key = Base64.getEncoder().encodeToString(seed.getBytes());

        des3_9.setText(key);

        String secret_pwd = HMACUtils.bytesToHex(HMACUtils.HMACMD5(key, clear_pwd));
        if (toUpper5.isSelected()) {
            des3_11.setText(secret_pwd.toUpperCase());
        } else {
            des3_11.setText(secret_pwd.toLowerCase());
        }
    }

    public void HMAC_SHA1() throws NoSuchAlgorithmException, InvalidKeyException {
        String seed = des3_12.getText();
        String clear_pwd = des3_13.getText();

        String key;

        if (seed.isEmpty()) {
            seed = (new SecureRandom()).toString();
        }

        key = Base64.getEncoder().encodeToString(seed.getBytes());

        des3_12.setText(key);

        String secret_pwd = HMACUtils.bytesToHex(HMACUtils.HMACSHA1(key, clear_pwd));
        if (toUpper6.isSelected()) {
            des3_14.setText(secret_pwd.toUpperCase());
        } else {
            des3_14.setText(secret_pwd.toLowerCase());
        }
    }

    public void HMAC_SHA2() throws NoSuchAlgorithmException, InvalidKeyException {
        String seed = des3_15.getText();
        String clear_pwd = des3_16.getText();

        String key;

        if (seed.isEmpty()) {
            seed = (new SecureRandom()).toString();
        }

        key = Base64.getEncoder().encodeToString(seed.getBytes());

        des3_15.setText(key);

        String secret_pwd = HMACUtils.bytesToHex(HMACUtils.HMACSHA256(key, clear_pwd));
        if (toUpper7.isSelected()) {
            des3_17.setText(secret_pwd.toUpperCase());
        } else {
            des3_17.setText(secret_pwd.toLowerCase());
        }
    }

    public void HMAC_SHA3() {
        String seed = des3_18.getText();
        String clear_pwd = des3_19.getText();

        String key;

        if (seed.isEmpty()) {
            seed = (new SecureRandom()).toString();
        }

        key = Base64.getEncoder().encodeToString(seed.getBytes());

        des3_18.setText(key);

        String secret_pwd = HMACUtils.bytesToHex(HMACUtils.HMACSHA3(key, clear_pwd));
        if (toUpper8.isSelected()) {
            des3_20.setText(secret_pwd.toUpperCase());
        } else {
            des3_20.setText(secret_pwd.toLowerCase());
        }
    }

    public void SM3hash(){
        String clear_pwd = des3_21.getText();

        String secret_pwd = SM3Utils.hmacSm3Hex("SM3".getBytes(), clear_pwd.getBytes());

        if (toUpper9.isSelected()) {
            des3_22.setText(secret_pwd.toUpperCase());
        } else {
            des3_22.setText(secret_pwd.toLowerCase());
        }
    }





    /** 数字签名 **/
    public void RSASGenKey() throws NoSuchAlgorithmException {
        KeyPair key = RSAUtils.generateKeyPair(2048);
        des4_1.setText(org.apache.commons.codec.binary.Base64.encodeBase64String(key.getPublic().getEncoded())); // 公钥
        des4_2.setText(org.apache.commons.codec.binary.Base64.encodeBase64String(key.getPrivate().getEncoded())); // 私钥
    }
    public void rsaSign() throws Exception {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey;
        try {
            String privateKeyStr = des4_2.getText();
            byte[] privateKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(privateKeyStr);
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        }
        catch (Exception e) {
            des4_4.setText("私钥信息被篡改，无法正常签名！");
            return;
        }

        String clear_pwd = des4_3.getText();
        des4_4.setText(Base64.getEncoder().encodeToString(RSAUtils.sign(clear_pwd.getBytes(), privateKey)));
    }
    public void rsaVer() {

        String publicKeyStr = des4_1.getText();

        PublicKey publicKey;
        try {
            byte[] publicKeyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        }
        catch (Exception e) {
            des4_6.setText("公钥信息被篡改，无法正常验签！");
            return;
        }

        try {
            des4_6.setText(String.valueOf(RSAUtils.verify(des4_3.getText().getBytes(), Base64.getDecoder().decode(des4_4.getText()), publicKey)));
        }
        catch (Exception e) {
            des4_6.setText("验签失败，请检查公私钥对以及签名是否配套！");
        }
    }



    public void ECCSKeyPair() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyPair keypair = ECCUtils.initKey(256, "EC");

        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String publicKeyBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(publicKey.getEncoded());
        String privateKeyBase64 = org.apache.commons.codec.binary.Base64.encodeBase64String(privateKey.getEncoded());

        des4_7.setText(publicKeyBase64);
        des4_8.setText(privateKeyBase64);
    }
    public void eccSign() {
        String clear_pwd = des4_9.getText();
        String privateKeyBase64 = des4_8.getText();

        try {
            des4_10.setText(ECCUtils.Sign(clear_pwd, privateKeyBase64, "SHA3-512withECDSA"));
        }
        catch (Exception e) {
            des4_10.setText("私钥信息被篡改，无法正常签名！");
        }
    }
    public void eccVer() {
        String clear_pwd = des4_9.getText();
        String secret_pwd = des4_10.getText();
        String publicKeyBase64 = des4_7.getText();

        try {
            des4_11.setText(String.valueOf(ECCUtils.Verify(clear_pwd, secret_pwd, publicKeyBase64, "SHA3-512withECDSA")));
        }
        catch (Exception e) {
            des4_11.setText("验签失败，请检查公私钥对以及签名是否配套！！");
        }
    }



    public void SM2SKeyPair() throws Exception {

        String parmA =  new SecureRandom().toString();
        String parmB =  new SecureRandom().toString();

        String[] keys = SM2Utils.KeyExchange(parmA, parmB);

        des4_12.setText(keys[0]);
        des4_14.setText(keys[1]);
    }
    public void SM2Sign() {
        String clear_pwd = des4_15.getText();
        String key = des4_14.getText();

        PrivateKey privateKey;
        try {
            privateKey = SM2Utils.CPrivateKey(key);
        }
        catch (Exception e) {
            des4_16.setText("私钥信息被篡改，无法正常签名！");
            return;
        }

        byte[] cipherTxt= SM2Utils.signByPrivateKey(clear_pwd.getBytes(), privateKey);
        if (cipherTxt != null) {
            des4_16.setText(Base64.getEncoder().encodeToString(cipherTxt));
        }
    }
    public void SM2Ver() {
        String clear_pwd = des4_15.getText();
        String secret_pwd = des4_16.getText();
        String key = des4_12.getText();

        PublicKey publicKey;
        try {
            publicKey = SM2Utils.CPublicKey(key);
        }
        catch (Exception e) {
            des4_17.setText("公钥信息被篡改，无法正常验签！");
            return;
        }

        try {
            String clearTxt = String.valueOf(SM2Utils.verifyByPublicKey(clear_pwd.getBytes(), publicKey, Base64.getDecoder().decode(secret_pwd)));
            des4_17.setText(clearTxt);
        }
        catch (Exception e) {
            des4_17.setText("验签失败，请检查公私钥对以及签名是否配套！");
        }
    }




    @Override
    public void initialize(URL location, ResourceBundle resources) {

//        Image image = new Image(Objects.requireNonNull(getClass().getResourceAsStream("../stage/logo.png")));
//
//        iconImageView.setImage(image);
    }

}
