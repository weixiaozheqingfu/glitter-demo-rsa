package com.glitter.demo.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * AES256加密算法
 *
 */
public class AES256Coder {

//    private static final Logger logger = LoggerFactory.getLogger(AES256Coder.class);

    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    public static final Integer KEY_LENGTH = 256;

    public static byte[] initkey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM, "BC");
        SecretKey secretKey = kg.generateKey();
        return secretKey.getEncoded();
    }

    public static Key toKey(byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        return secretKey;
    }

    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        Key k = toKey(key);
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, k);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, k);
        return cipher.doFinal(data);
    }
    
}