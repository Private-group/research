package com.research.security.demo;

import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MD5 {
	private static final String HMAC_SHA1 = "HmacSHA1";
	/**   
     * 生成签名数据   
     *    
     * @param data 待加密的数据   
     * @param key  加密使用的key   
     * @throws InvalidKeyException   
     * @throws NoSuchAlgorithmException   
     */    
    public static String getSignature(String data,String key) throws Exception{  
     byte[] keyBytes=key.getBytes();  
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, HMAC_SHA1);     
        Mac mac = Mac.getInstance(HMAC_SHA1);     
        mac.init(signingKey);     
        byte[] rawHmac = mac.doFinal(data.getBytes());  
        StringBuilder sb=new StringBuilder();  
        for(byte b:rawHmac){  
         sb.append(byteToHexString(b));  
        }  
        return sb.toString();     
    }  
    
    private static String byteToHexString(byte ib){  
     char[] Digit={  
       '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'  
     };  
     char[] ob=new char[2];  
     ob[0]=Digit[(ib>>>4)& 0X0f];  
     ob[1]=Digit[ib & 0X0F];  
     String s=new String(ob);  
     return s;           
    }       
	
    
	public static String hex(byte[] array) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < array.length; ++i) {
			sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100)
					.toUpperCase().substring(1, 3));
		}
		return sb.toString();
	}

	public static String encrypt(String message) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			return hex(md.digest(message.getBytes("ISO8859-1")));
		} catch (Exception e) {
		}
		return null;
	}
	/** 
    * 获取MD5 结果字符串 
    *  
    * @param source 
    * @return 
    */  
   public static String encode(byte[] source) {  
       String s = null;  
       char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };  
       try {  
           java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");  
           md.update(source);  
           byte tmp[] = md.digest();   
           char str[] = new char[16 * 2];   
           int k = 0;   
           for (int i = 0; i < 16; i++) {   
               byte byte0 = tmp[i];   
               str[k++] = hexDigits[byte0 >>> 4 & 0xf];   
               str[k++] = hexDigits[byte0 & 0xf];   
           }  
           s = new String(str);   
       } catch (Exception e) {  
           e.printStackTrace();  
       }  
       return s;  
   } 
	public static String getSecretKey(String content) {
		String SecretKey = "";
		if (content != null && content.length() >= 8) {
			SecretKey = content.substring(3, 8);
			if (SecretKey.equals("cm003")) {
				SecretKey = "boyaabsk";
			} else {
				SecretKey = SecretKey + "bsk";
			}
		}
		return SecretKey;
	}

	public static void main(String[] args) {
		System.out.println(encrypt("Hello world"));
	}
}
