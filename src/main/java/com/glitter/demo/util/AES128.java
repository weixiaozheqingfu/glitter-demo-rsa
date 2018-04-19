package com.glitter.demo.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AES128 {

	// 切换AES下的几种加密模式可以参考博文https://www.cnblogs.com/dava/p/6416638.html
	// https://www.cnblogs.com/lianghui66/archive/2013/03/07/2948494.html


	/**
	 * 加密
	 * 
	 * @param content
	 *            需要加密的内容
	 * @return
	 */
	public static String encrypt(String content, String strKey) {

		try {
			// 创建密码器
			Cipher cipher = Cipher.getInstance("AES");
			// 初始化
			cipher.init(Cipher.ENCRYPT_MODE, genKey(strKey));

			byte[] byteContent = content.getBytes("utf-8");
			byte[] result = cipher.doFinal(byteContent);
			// 加密
			return parseByte2HexStr(result);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;

	}

	/**
	 * 解密
	 * 
	 * @param content
	 *            待解密内容
	 * @return
	 */
	public static String decrypt(String content, String strKey) {

		try {
			byte[] decryptFrom = parseHexStr2Byte(content);

			// 创建密码器
			Cipher cipher = Cipher.getInstance("AES");
			// 初始化
			cipher.init(Cipher.DECRYPT_MODE, genKey(strKey));

			byte[] result = cipher.doFinal(decryptFrom);
			// 加密
			return new String(result);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 根据密钥获得 SecretKeySpec
	 * 
	 * @return
	 */
	private static SecretKeySpec genKey(String strKey) {

		byte[] enCodeFormat = { 0 };
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(strKey.getBytes());
			kgen.init(128, secureRandom);
			SecretKey secretKey = kgen.generateKey();
			enCodeFormat = secretKey.getEncoded();

		} catch (Exception e) {
			e.printStackTrace();
		}

		return new SecretKeySpec(enCodeFormat, "AES");
	}

	/**
	 * 将二进制转换成16进制
	 * 
	 * @param buf
	 * @return
	 */
	private static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * 将16进制转换为二进制
	 * 
	 * @param hexStr
	 * @return
	 */
	private static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1) {return null;}
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

	public static void main(String[] args) {

		System.out.println("Generate password success!");
		System.out.print("password:");
		String strKey = "Blink001";
		String content = "{\"appkey\":\"e0x9wycfxmq3q\",\"userId\":\"blink1\"}";
		System.out.println(AES128.encrypt(content, strKey) + "\n");
		System.out.println(AES128.decrypt("7ADACEBF7DE70F655BE8277B20459398DDD2B361582FBA0C0D47E061171B00A22DD1D1BA1534EE043AC232C69222608B", strKey) + "\n");

	}

}
