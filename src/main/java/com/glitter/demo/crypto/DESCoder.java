package com.glitter.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;

public class DESCoder {

	public static final String ENCODE_TYPE = "DES";
	public static final String ENCODE_TYPE_PADDING = "DES/ECB/PKCS5Padding";

	public static byte[] encrypt(byte[] data, String key) throws Exception {
		SecureRandom random = new SecureRandom();
		DESKeySpec desKey = new DESKeySpec(key.getBytes());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ENCODE_TYPE);
		SecretKey securekey = keyFactory.generateSecret(desKey);
		Cipher cipher = Cipher.getInstance(ENCODE_TYPE_PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
		return cipher.doFinal(data);
	}

	public static byte[] decrypt(byte[] data, String key) throws Exception {
		SecureRandom random = new SecureRandom();
		DESKeySpec desKey = new DESKeySpec(key.getBytes());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ENCODE_TYPE);
		SecretKey securekey = keyFactory.generateSecret(desKey);
		Cipher cipher = Cipher.getInstance(ENCODE_TYPE_PADDING);
		cipher.init(Cipher.DECRYPT_MODE, securekey, random);
		return cipher.doFinal(data);
	}

}