package com.glitter.demo.crypto;

import com.google.common.collect.Maps;
import com.syswin.systoon.framework.security.crypto.sm.sm3.SM3Digest;
import com.syswin.systoon.framework.security.crypto.sm.sm4.SM4Coder;
import com.syswin.systoon.framework.util.HexUtils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Map;

public class CryptoClient {
	
  private static final Logger logger = LoggerFactory.getLogger(CryptoClient.class);

  public static final String CHARSET = "UTF-8";
  
  public static String encryptWithAES(String data, String key) {
		try {
			byte[] aesKey = HexUtils.hexStr2ByteArray(key);
			byte[] bytes = data.getBytes();
			byte[] encrypt = AES256Coder.encrypt(bytes, aesKey);
			return HexUtils.byteArray2HexStr(encrypt);
		} catch (Exception e) {
			logger.error("AES encrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String decryptWithAES(String data, String key) {
		try {
			byte[] aesKey = HexUtils.hexStr2ByteArray(key);
			byte[] bytes = HexUtils.hexStr2ByteArray(data);
			byte[] decrypt = AES256Coder.decrypt(bytes, aesKey);
			return new String(decrypt);
		} catch (Exception e) {
			logger.error("AES decrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String encryptWithDES(String data, String key, boolean isUrlSafe) {
		try {
			String md5 = MD5Coder.md5(key);
			byte[] encrypt = DESCoder.encrypt(data.getBytes(CHARSET), md5);
			if (isUrlSafe) {
				return Base64.encodeBase64URLSafeString(encrypt);
			}
			return Base64.encodeBase64String(encrypt);
		} catch (Exception e) {
			logger.error("DES encrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String decryptWithDES(String data, String key) {
		try {
			String md5 = MD5Coder.md5(key);
			byte[] encodeBase64 = Base64.decodeBase64(data
					.getBytes(CHARSET));
			byte[] encrypt = DESCoder.decrypt(encodeBase64, md5);
			return new String(encrypt, CHARSET);
		} catch (Exception e) {
			logger.error("DES decrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String encryptWithSM4(String data, String key, boolean isUrlSafe) {
		try {
			SM4Coder sm4 = new SM4Coder();
			sm4.setSecretKey(key);
			byte[] encrypt = sm4.encryptData_ECB(data).getBytes(CHARSET);
			if (isUrlSafe) {
				return Base64.encodeBase64URLSafeString(encrypt);
			}
			return Base64.encodeBase64String(encrypt);
		} catch (Exception e) {
			logger.error("SM4 encrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String decryptWithSM4(String data, String key) {
		try {
			SM4Coder sm4 = new SM4Coder();
			sm4.setSecretKey(key);
			byte[] encodeBase64 = Base64.decodeBase64(data
					.getBytes(CHARSET));
			return sm4.decryptData_ECB(new String(encodeBase64, CHARSET));
		} catch (Exception e) {
			logger.error("SM4 decrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String encryptWithRSA(String data, String key, boolean isUrlSafe) {
		try {
			byte[] encrypt = RSACoder.encryptByPublicKey(data.getBytes(CHARSET), key);
			if (isUrlSafe) {
				return Base64.encodeBase64URLSafeString(encrypt);
			}
			return Base64.encodeBase64String(encrypt);
		} catch (Exception e) {
			logger.error("RSA encrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String decryptWithRSA(String data, String key) {
		try {
			byte[] encodeBase64 = Base64.decodeBase64(data
					.getBytes(CHARSET));
			byte[] encrypt = RSACoder.decryptByPrivateKey(encodeBase64, key);
			return new String(encrypt, CHARSET);
		} catch (Exception e) {
			logger.error("RSA decrypt error: " + e.getMessage(), e);
		}
		return null;
	}

	public static Map<String, String> genRSAKeyMap(){
		try {
			Map<String, Object> keys = RSACoder.initKey();
			Map<String, String> keyMap = Maps.newHashMap();
			keyMap.put("pubKey", RSACoder.getPublicKey(keys));
			keyMap.put("privateKey", RSACoder.getPrivateKey(keys));
			return keyMap;
		} catch (Exception e) {
			logger.error("RSA key generated error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String digestWithMD5(String data){
		try {
			return MD5Coder.md5(data);
		} catch (Exception e) {
			logger.error("MD5 digest error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String digestWithSHA(String data){
		try {
			return SHACoder.sha256(data);
		} catch (Exception e) {
			logger.error("SHA digest error: " + e.getMessage(), e);
		}
		return null;
	}

	public static String digestWithSM3(String data){
		try {
			SM3Digest digest = new SM3Digest();
			byte[] dbyte = data.getBytes(CHARSET);
			digest.update(dbyte, 0, dbyte.length);
			byte[] sign = new byte[32];
			digest.doFinal(sign, 0);
			return new String(Hex.encode(sign), CHARSET);
		} catch (Exception e) {
			logger.error("SM3 digest error: " + e.getMessage(), e);
		}
		return null;
	}

	public static void main(String args[]){
		String key = "07e1ef27e3b14c388414e11aaaa9ed45";
		String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf1/IsN6zxbsLgkovLD0aLOt+uzN1j2DkSq+YTav0kQCnygUd7wEo7x9v5wCqExhWw+b7f2JLp5nw/vRHrxRDreswdwWdVmxTjQXINelF4PzlIgBnBHWAshHBPCVh+J85nQUqrg72bBOWRA/0cwdvOKSd9sc4qGewK7qdUcxbg9wIDAQAB";
		String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJ/X8iw3rPFuwuCSi8sPRos6367M3WPYORKr5hNq/SRAKfKBR3vASjvH2/nAKoTGFbD5vt/YkunmfD+9EevFEOt6zB3BZ1WbFONBcg16UXg/OUiAGcEdYCyEcE8JWH4nzmdBSquDvZsE5ZED/RzB284pJ32xzioZ7Arup1RzFuD3AgMBAAECgYBIzviEo6enIaiq2pXKnN6pNNwGp1KA1FDK7HoUhjtgc8mnqLOC7wfhSxwsGxhC+mePAXOsSt5ApLgb4Gd1WYJmx3VnoizgLErLarFde5euqUHQR9cvx5SEFpoPxLfb9YfkLSi8UT7leaZ/7yZiMz3VfDyfM1FkNmZcom1xe+IUQQJBAOBl52J1E5kmZCxFBxzpXf2CVJVM1hJ9rpM2LHHSdyT4yuDQBWqi3kHWm9ggfzcOKzu0xT8zVGqi69dLCtlW278CQQC2WrHLizokaiAWD6BFsY8vohVqppI1n4lFC0qzuTN0jHaRAmfbMe/Vcd9ozCxC3tmfUriV3N8ETLJ7iltKEajJAkBwsZy3rJZwFoC+XthIo8aJNzflVxY3aRkQY2eEri8ZyTySFMZznGHEbNQNgZyB+MKrlIhuygd+Gl4Y3F4RcnafAkA1DwyemgMv50UwxhkvTivIg1PR9WejfKkXUuLIioHDTr+ND/MiH1SWeYy01HuodWlC53HYAS1O9fYU5jwLwDmpAkEAn/3rtcJelHvLQlyAeTMVcWQ/8uSKkPJkxskZQQHBANbIk2eh1Z3Sad4Sn/b2ibuYecROM0wmf72REu7fbX8m1A==";
		String data = "100:07e1ef27e3b14c388414e11aaaa9ed45" + ":" + new Date().getTime();
		System.out.println("----DES ENCRYPT----");
		String encryptedData =  encryptWithDES(data, key, false);
		System.out.println("encrypted data:" + encryptedData);
		String decryptedData =  decryptWithDES(encryptedData, key).toString();
		System.out.println("decrypted data:" + decryptedData);
		
		System.out.println("----AES ENCRYPT----");
		String encryptedData1 =  encryptWithAES(data, key);
		System.out.println("encrypted data:" + encryptedData1);
		String decryptedData1 =  decryptWithAES(encryptedData1, key).toString();
		System.out.println("decrypted data:" + decryptedData1);
		
		System.out.println("----RSA ENCRYPT----");
		String encryptedData2 =  encryptWithRSA(data, pubKey, false);
		System.out.println("encrypted data:" + encryptedData2);
		String decryptedData2 =  decryptWithRSA(encryptedData2, privateKey);
		System.out.println("decrypted data:" + decryptedData2);

		String smKey = "07e14c388414ed45";
		System.out.println("----SM4 ENCRYPT----");
		String smEncrypt =  encryptWithSM4(data,smKey, false);
		System.out.println("encrypted data:" + smEncrypt);
		String smDecrypt =  decryptWithSM4(smEncrypt, smKey);
		System.out.println("decrypted data:" + smDecrypt);

		String origin = "123rty456EEEEE444";
		System.out.println("----SM3 ENCRYPT----");
		String sm3Encrypt = digestWithSM3(origin);
		System.out.println("encrypted data:" + sm3Encrypt);
	}
	
	
}