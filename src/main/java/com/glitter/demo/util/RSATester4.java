package com.glitter.demo.util;


import com.glitter.demo.bean.Message;
import com.glitter.demo.bean.Person;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 名词说明：
 * A公钥:publicKeyA
 * A私钥:privateKeyA
 * B公钥:publicKeyB
 * B私钥:privateKeyB
 *
 * Message:消息体
 * data:数据
 * sign:签名
 *
 *
 * 演示A与B进行通信过程。
 * A使用publicKeyB加密source，并使用privateKeyA做数字签名
 *
 * B使用publicKeyA验签，如果验签通过则使用privateKeyB解密
 *
 * 演示场景，数据明文，就加数字签名，目的是防止数据被篡改，但是数据本身并不敏感，并非对外不可见，数据不是秘密，但要保证传输的安全可靠性。
 * 同时保证数据的来源可靠性。
 *
 * 数据量大的情况下使用RSA加密耗时很长。
 *
 *
 * 为什么叫做签名，很形象，只有发送者的私钥进行的加密，只有发送者的公钥可以解开。发送者的私钥加密后的数据就相当于是发送者对数据的签名。
 * 当收到数据后，一验证，就知道是发送者发送的消息，而不是其他人进行伪造的。
 *
 * 就好像一个我们对一个合同签名后，只要进行笔记验证，就可以知道该签名是否为签名者真迹。
 *
 *
 * by limengjun
 */
public class RSATester4 {

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
        // 签名
        testA();
        // 验签
        testB();
    }


    /**
     * 签名
     *
     * Message:1.json化，2.encode
     * data:json化后再encode
     * summary:md5原始数据
     * sign:encode后的数据
     *
     * @throws Exception
     */
    static void testA() throws Exception {
        // 1.准备数据
        Person data = new Person();
        data.setName("张三丰");
        data.setAge(111);
        data.setSex(new Byte("1"));
        data.setIdNumber("110110124701016666");

        Gson gson = new Gson();
        String dataStr = gson.toJson(data);
        String dataStr1 = RSAUtils.encode(dataStr.getBytes());

        // 2.A提取数据data的数据摘要h(data),并使用A的私钥对摘要h(data)进行加密,生成签名sign(经过base64的encode编码后的数据)
        String summary = DigestUtils.md5Hex(dataStr);
        byte[] summaryBytes = summary.getBytes("UTF-8");
        byte[] signBytes = RSAUtils.encryptByPrivateKey(summaryBytes,privateKeyA);
        String sign = RSAUtils.encode(signBytes);

        // 3.使用B的公钥对消息体进行加密，消息体包括数据和签名。
        Message message = new Message();
        message.setData(dataStr1);
        message.setSign(sign);
        String messageJson = gson.toJson(message);
        String messageEncrypted = RSAUtils.encode(messageJson.getBytes("UTF-8"));

        // 将加密信息及数字签名发送至B,此处仅为演示故将信息放入map中进行数据传递。
        map.put("message",messageEncrypted);
    }

    /**
     * 验签
     *
     * Message:1.解码decode,2.再json数据
     * data:1.先解码decode数据，2.再json转对象。
     * sign:encode后的数据  1.解码decode数据，
     * summary:md5原始数据
     *
     * 也可以先解密再验签 验签失败也可以将被篡改的数据记录下来做分析 可以分析破坏者想干什么
     * @throws Exception
     */
    static void testB() throws Exception {

        // 1.B接收到message信息
        String messageEncrypted = String.valueOf(map.get("message"));
        // 解码
        byte[] messageBytesEncrypted = RSAUtils.decode(messageEncrypted);
        String messageOriginal = new String(messageBytesEncrypted,"UTF-8");
        Gson gson = new Gson();
        Message message = gson.fromJson(messageOriginal,Message.class);

        // 2.B使用A的公钥解密数字签名sign解密得到H(data)。这是验签的一部分,解密成功说明消息是A发送的。
        String data = message.getData();
        String dataJson = new String(RSAUtils.decode(data));

        String sign = message.getSign();
        byte[] signBytes = RSAUtils.decode(sign);
        byte[] summaryBytes = null;
        String summaryA = null;
        try{
            summaryBytes = RSAUtils.decryptByPublicKey(signBytes,publicKeyA);
            summaryA = new String(summaryBytes,"UTF-8");
        }catch (Exception e){
            System.out.println("验签失败");
            // TODO 可以触发报警机制...
            throw new Exception("验签失败");
        }

        // 3.B使用相同的方法提取消息data的消息摘要h(data)
        String summaryB = DigestUtils.md5Hex(dataJson);
        // 4.B比较两个消息摘要。相同则验证成功;不同则验证失败。
        if(!summaryA.equals(summaryB)){
            System.out.println("验签失败,数据被篡改");
            // TODO 可以触发报警机制...
            throw new Exception("验签失败,数据被篡改");
        }

        // 4.B验签成功,数据data可以继续后续业务处理...
        System.out.println("解密结果:"+dataJson);
    }
    
}
