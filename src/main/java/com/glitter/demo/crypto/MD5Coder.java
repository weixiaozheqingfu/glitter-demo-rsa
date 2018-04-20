package com.glitter.demo.crypto;

import org.apache.commons.codec.digest.DigestUtils;

public class MD5Coder {
	
	private static final String CHAR_SET = "UTF-8";

	public static final String md5(String data) throws Exception {
		return md5(data, CHAR_SET);
	}

	public static final String md5(String data, String charSet) throws Exception {
		return DigestUtils.md5Hex(data.getBytes(charSet)).toUpperCase();
	}
	
}