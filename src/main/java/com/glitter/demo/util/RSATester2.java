package com.glitter.demo.util;


import java.util.HashMap;
import java.util.Map;

/**
 * 名词说明：
 * A公钥:publicKeyA
 * A私钥:privateKeyA
 * B公钥:publicKeyB
 * B私钥:privateKeyB
 *
 * source:待加密信息
 * sign:数字签名
 *
 *
 * 演示A与B进行通信过程。
 * A使用publicKeyB加密source，并使用privateKeyA做数字签名
 *
 * B使用publicKeyA验签，如果验签通过则使用privateKeyB解密
 *
 * by limengjun
 */
public class RSATester2 {

    static String publicKeyA;
    static String privateKeyA;

    static String publicKeyB;
    static String privateKeyB;

    static Map<String,Object> map = new HashMap<>();

    static {
        try {
            Map<String, Object> keyMapA = RSAUtils.genKeyPair();
            publicKeyA = RSAUtils.getPublicKey(keyMapA);
            privateKeyA = RSAUtils.getPrivateKey(keyMapA);
            System.err.println("A公钥: \n\r" + publicKeyA);
            System.err.println("A私钥: \n\r" + privateKeyA);

            Map<String, Object> keyMapB = RSAUtils.genKeyPair();
            publicKeyB = RSAUtils.getPublicKey(keyMapB);
            privateKeyB = RSAUtils.getPrivateKey(keyMapB);
            System.err.println("B公钥: \n\r" + publicKeyB);
            System.err.println("B私钥: \n\r" + privateKeyB);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) throws Exception {
        // 加密签名
        testA();
        // 验签解密
        testB();
    }

    /**
     * 加密签名
     * @throws Exception
     */
    static void testA() throws Exception {
        String source = "这是绝密";
        System.out.println("\r正文信息:\r\n" + source);
        byte[] data = source.getBytes();
        // 使用B公钥加密
        byte[] encodedData = RSAUtils.encryptByPublicKey(data, publicKeyB);
        System.out.println("B公钥加密后的信息:\r\n" + new String(encodedData));
        // 使用A私钥对加密信息进行签名
        String sign = RSAUtils.sign(encodedData, privateKeyA);
        System.out.println("数字签名信息:\r" + sign);

        // 将加密信息及数字签名发送至B,此处仅为演示故将信息放入map中进行数据传递。
        map.put("data",encodedData);
        map.put("sign",sign);

    }

    /**
     * 验签解密
     *
     * 也可以先解密再验签 验签失败也可以将被篡改的数据记录下来做分析 可以分析破坏者想干什么
     * @throws Exception
     */
    static void testB() throws Exception {
        byte[] data = (byte[])map.get("data");
        String sign = map.get("sign").toString();

        // 使用A公钥进行验签
        boolean flag = RSAUtils.verify(data,publicKeyA,sign);
        // 如果验签失败,则进行相应支流的业务相应，例如抛出异常，触发报警等
        if(!flag){
            System.out.println("验签失败");
            // TODO ...
            throw new Exception("验签失败");
        }
        // 如果验签成功,则进行数据解密
        System.out.println("验签成功");
        byte[] data1 = RSAUtils.decryptByPrivateKey(data,privateKeyB);
        String result = new String(data1);
        System.out.println("解密数据结果:"+result);
    }
    
}
