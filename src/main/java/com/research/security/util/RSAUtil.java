package com.research.security.util;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class RSAUtil {
    private static final String KEY_ALGORITHM = "RSA";
    /** 貌似默认是RSA/NONE/PKCS1Padding，未验证 */
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String PUBLIC_KEY = "publicKey";
    private static final String PRIVATE_KEY = "privateKey";

    /** RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024 */
    private static final int KEY_SIZE = 2048;

    private static final String PRIVATE_KEY_VALUE = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCEY82eBhaCZqdknwXqcvWBcV/OxsbpJ1/gMw5u9nF3JNLP+P5+epRDllt0cjBRcVx9KyHmyCjKw/aiPpN5cAWAQON4OV3aN9IcWY+LFaidFcNzWCn2FC0hc3gHf96yz6RQuVEz85q30M8azU3A9QjtYnTd5RSUJ8UYCDBQ8Fu8jkL+WzmC1C1PFjJbFXovRajSmPsIPYgjXChFWtHziInFFuyX3KDJBDgcu4qOIjLntDt3HNlVcPTLtZ5a/Gi9lyRGG12x+qcGPilLN2CAz8XSi+i/f3KTzLxNYNxIIfAm6mTFLbBH5Gk23WMVc1yoacFEpBwEi8GeBOXiRzJS008NAgMBAAECggEBAIJvupRpNyA/d8mBjFiT7yMbyuN1oWDyNFo2s4/MK7rRgwr5LfT7XLzClVTDdKupXxDLwFka+GXecU8lDDPnlOPqCrPXAYsQ2GiqLO1B56DtYmZwhNc4xcZhd+8boxTV0/TcwQ7IgrV8e7DSejsUsTkBeldtbrsR+/RTjRcR2bCJkwhnxIRwHCH7eDAtyyzkVW2msIlHa0TziqIh/xFxM2/zyM1K7GCbMtOLgcBvjSq+Y3icjP6NtrzZz3KN6lzVXvn/R24AhgMloXm/2HRIBVo5AyAKxS8cRV4CV4OlW8AcDnAMqZFiHNTQabsJ0BzgctiGtQu4Ni3ZWsf57+49JIECgYEA/+EsdSr0RW/o9WKTMpm7/MxhSpr0EAt0phQxnWlSG5vGFP0nzS2bLpH8uZMIbiOCPUIOUbxK6NX/5q/3G4LBfwXyKliPPUk+q++AT4M+xLdVRvNew+QNy0QodegoobDt03HzTo4dGvl6UkxPJzAYiuK47rJTfD2q3ytwb9ZT+7ECgYEAhHPAodVzINYJJJjjewLo3u5Tat7aCxY0SE8RbZ4naJkrsrBUszWhZsvkTylKxA0z7Uo4XdyNr78vbJ96Yhzi53isMDI9nu4K6dexkgxun72Q5QzZAPxqzQ8vMh7Oh6ZRIeCUqst0UuYKOP9tguvivc3zRk4RWJjRkSnwXTIbjB0CgYEA7XF3fta4TAMYKzUpIOh2AJVrpv55grYOrdrJW6gTMFlyC6ILoCM1AJcp7M7bINFElzHH9eMDpGKJD/m0FcxVYFkVKmR5r0ZbqNMbvy0sPwFdWfSWuLLUdg4ueZNQuRJk7zSrsfbAXXqqHtp/DP9dluvi7mV+gSj8ehFmSfGah1ECgYByFDhvqqZUO8T4Lm6PPnxPtjlGrNZkAiXZubArF7Kdln9akiEBkUmIfkgQHmJ05WI6GFjgDtxB6IryJZGE+5g7AWZcxIjqX+AqdEpOnkKRdvZbMWueO8nJADEIHByKHSd35DRnvoBb/iID4Yvy3TQXglDr1sV953FodBTAUC4FyQKBgBEM2gnvwf13o7Jw4BpzZYh++HVnKbwVbrEB71VydDFdANIl7YZkgdsBi9ROC/GJhJRRtie70O65bg6j9j5/g4hsAwLOUBHjdqHyexoWXWgYQnLHjiLqnLxvSn8J0aqTsBQNwOX+PM1ezXKe/tGPFzjBd2BHs70jrXobgzpOsgUd";
    
    /*public static void main(String[] args) {
        Map<String, byte[]> keyMap = generateKeyBytes();

        // 加密
       PublicKey publicKey = restorePublicKey(keyMap.get(PUBLIC_KEY));//(keyMap.get(PUBLIC_KEY));
       System.out.println("public key: " + Base64.encodeBase64String(publicKey.getEncoded()));
       System.out.println("public key: " + Base64.encodeBase64String(keyMap.get(PUBLIC_KEY)));
        //byte[] encodedText = RSAEncode(publicKey, PLAIN_TEXT.getBytes());
        //System.out.println("Base64 encoded: " + Base64.encodeBase64String(encodedText));

        // 解密
       PrivateKey privateKey = restorePrivateKey(keyMap.get(PRIVATE_KEY));
        System.out.println("private key: " + Base64.encodeBase64String(privateKey.getEncoded()));
        System.out.println("private key: " + Base64.encodeBase64String(keyMap.get(PRIVATE_KEY)));
//        System.out.println("RSA decoded: "
//                + RSADecode(privateKey, Base64.decodeBase64("XXGx9pg2zZjGNEl5iYY7uIDT74nJK45c+89kWhVME+DL9x+Wnu6e0F+kJh/AtO7UxOBFOYDfLsZ0I4pE02vLRr5ZtBSvlaQwL94R+WELI3tBFhtF8RTqyQdBGtwGEqHpz3w+psePoUlu4UZgiv/jnlPjA/tT1QFvwU9ylkSMKIR7KgqBV+uIoXrKCIJ1MmrxYVlFCViVTvMUNWJqgmVIjYNZ+cU9SelcotG5KqNtqVDecg7iqoMjN3k9FxbtJxIUp0ZATeSk3gm3x+ygPz0+RgZ4VHKiD/zKdwRq19MBW0U12X4lEV5eq8Psd+Z88IO6bty4oUzlyrq159GAp1khSw==&requestId=17654104729944087")));
    }*/
    
    public static String[] genKeyPairs() {
    	Map<String, byte[]> keyMap = generateKeyBytes();
    	String publicKey = Base64.encodeBase64String(keyMap.get(PUBLIC_KEY));
        //System.out.println("public key: " + Base64.encodeBase64String(publicKey.getEncoded()));
    	String privateKey = Base64.encodeBase64String(keyMap.get(PRIVATE_KEY));
        //System.out.println("private key: " + Base64.encodeBase64String(privateKey.getEncoded()));
        return new String[]{publicKey, privateKey};
    }
    
    /**
     * 解密密码
     * @param password
     * @return
     */
    public static String decodePassword(String password) {
    	return decodePassword(password, PRIVATE_KEY_VALUE);
    }
    
    /**
     * 解密密码
     * @param password
     * @return
     */
    public static String decodePassword(String password, String privateKey) {
    	return RSADecode(restorePrivateKey(Base64.decodeBase64(privateKey)), Base64.decodeBase64(password));
    }
    

    /**
     * 生成密钥对。注意这里是生成密钥对KeyPair，再由密钥对获取公私钥
     * 
     * @return
     */
    private static Map<String, byte[]> generateKeyBytes() {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Map<String, byte[]> keyMap = new HashMap<String, byte[]>();
            keyMap.put(PUBLIC_KEY, publicKey.getEncoded());
            keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 还原公钥，X509EncodedKeySpec 用于构建公钥的规范
     * 
     * @param keyBytes
     * @return
     */
    private static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 还原私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
     * 
     * @param keyBytes
     * @return
     */
    private static PrivateKey restorePrivateKey(byte[] keyBytes) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = factory
                    .generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密，三步走。
     * 
     * @param key
     * @param plainText
     * @return
     */
    private static byte[] RSAEncode(PublicKey key, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * 解密，三步走。
     * 
     * @param key
     * @param encodedText
     * @return
     */
    private static String RSADecode(PrivateKey key, byte[] encodedText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(encodedText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }
}