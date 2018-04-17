package com.glitter.demo.util;


import java.util.Map;

public class RSATester {

    static String publicKey;
    static String privateKey;

    static {
        try {
            Map<String, Object> keyMap = RSAUtils.genKeyPair();
            publicKey = RSAUtils.getPublicKey(keyMap);
            privateKey = RSAUtils.getPrivateKey(keyMap);
            System.err.println("公钥: \n\r" + publicKey);
            System.err.println("私钥: \n\r" + privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) throws Exception {
        test();
        testSign();
    }

    static void test() throws Exception {
        System.err.println("RSA测试");
        String source = "这是绝密,toon即将上线；这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线";
        System.out.println("\r正文信息:\r\n" + source);
        byte[] data = source.getBytes();
        // 公钥加密
        byte[] encodedData = RSAUtils.encryptByPublicKey(data, publicKey);
        System.out.println("加密后的信息:\r\n" + new String(encodedData));
        // 私钥解密
        byte[] decodedData = RSAUtils.decryptByPrivateKey(encodedData, privateKey);
        String target = new String(decodedData);
        System.out.println("解密收的信息: \r\n" + target);
    }

    static void testSign() throws Exception {
        System.err.println("RSA测试");
        String source = "这是绝密,toon即将上线；这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线这是绝密,toon即将上线";
        System.out.println("\r正文信息\r\n" + source);
        byte[] data = source.getBytes();
        // 私钥加密
        byte[] encodedData = RSAUtils.encryptByPrivateKey(data, privateKey);
        System.out.println("加密后的信息:\r\n" + new String(encodedData));
        // 公钥解密
        byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, publicKey);
        String target = new String(decodedData);
        System.out.println("解密收的信息: \r\n" + target);


        System.err.println("数字签名过程开始");
        String sign = RSAUtils.sign(encodedData, privateKey);
        System.err.println("数字签名信息:\r" + sign);
        boolean status = RSAUtils.verify(encodedData, publicKey, sign);
        System.err.println("验签结果:\r" + status);
    }
    
}
