package com.glitter.demo.crypto;

import org.apache.commons.codec.digest.DigestUtils;

public class SHACoder {
	
	private static final String CHAR_SET = "UTF-8";

	public static final String sha256(String data) throws Exception {
		return sha256(data, CHAR_SET);
	}

	public static final String sha256(String data, String charSet) throws Exception {
		return DigestUtils.sha256Hex(data.getBytes(charSet)).toUpperCase();
	}
	
}