package com.glitter.demo.util;


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
 * 演示场景，数据使用加密强度高安全性高可靠性高不易破解的对称加密算法进行加密，特点，比非对称加密速度快，尤其是数据量大的时候，
 * 缺点，对称加密为了保证秘钥的安全性，通常使用动态秘钥进行加密和解密，即秘钥每次都只使用一次，不会长期持有，因为秘钥是双方持有的，
 * 有任何一方泄露秘钥，则加密数据都是不安全的，长期持有固定对称秘钥，会大大降低秘钥安全性。
 *
 * 那么每次如果使用动态秘钥的话，就需要加密方每次都要生成对称秘钥并将加密数据和对称秘钥同时传送给数据接收方，问题就是要传输过程中对称秘钥的安全性，
 * 保证了对称秘钥的安全可靠，也就保证了数据的安全可靠（前提是安全可靠不易被破解的对称加密算法）。
 * 很明显对称秘钥不可以明文进行传输，有了RSA，我们可以将二者完美结合起来。可以使用RSA对对称秘钥进行加密，这样就能保证秘钥的安全可靠同时也保证了数据的加密速度。
 * 可谓是完美的结合，重要的事情再说一遍，前提是安全可靠不易被破解的对称加密算法，如果对称加密算法不行，人家不用破解你使用RSA加密的秘钥，直接破解你对称加密的数据就好了。
 *
 *
 * 锦上添花，更进一步增加安全性：
 * 1.Message信息中包括（String data,String secretKey,String sign）; 其中data是对称加密后的数据，secretKey是RSA加密后的对称秘钥，sign是签名数据。
 * 2.sign的签名规则可以设定复杂一点，例如
 *  （data+secretKey原始未加密时的对称秘钥值+只有双方一对一都知道的业务码，如appid+appsecret（该项非必须，但有安全性更高））做信息摘要，
 *  进而进一步对信息摘要做数字签名（可以手动使用发送方私钥机密的方式来手动实现对摘要信息的数字签名）
 *
 *  要明白一点，数据拦截者或者意图篡改者是不知道你的数据摘都是对哪些数据进行了摘要，我们不一定就只单单使用原始数据直接摘要的。而摘要又是不可逆的，
 *  所以篡改者除非事先知道规则，否则他永远无法重新生成新的摘要信息，退一步即便按照相同的规则伪造了数据和摘要信息，他也拿不到发送者的私钥，不使用
 *  发送者的私钥对摘要进行加密即签名，那么一切都是徒劳的，随便使用自己的私钥给摘要加密，接收者是会验签失败而发现的，
 *  由此可见对摘要信息设置复杂一点，是在安全性上锦上添花了，就是说连摘要他都不可能伪造，因为他不知道规则。
 *
 *
 *
 * by limengjun
 */
public class RSATester5 {

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
     *
     * Message:1.json化，2.加密，3.encode
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
//        String sign = new String(signBytes,"UTF-8");
        String sign = RSAUtils.encode(signBytes);

        // 3.使用B的公钥对消息体进行加密，消息体包括数据和签名。
        Message message = new Message();
        message.setData(dataStr1);
        message.setSign(sign);
        String messageJson = gson.toJson(message);
        byte[] messageBytes = messageJson.getBytes("UTF-8");
        byte[] messageBytesEncrypted = RSAUtils.encryptByPublicKey(messageBytes,publicKeyB);
        String messageEncrypted = RSAUtils.encode(messageBytesEncrypted);

        // 将加密信息及数字签名发送至B,此处仅为演示故将信息放入map中进行数据传递。
        map.put("message",messageEncrypted);
    }

    /**
     * 验签解密
     *
     * Message:1.解码decode,2.再解密数据，3.再json数据
     * data:1.先解码decode数据，2.再json转对象。
     * sign:encode后的数据  1.解码decode数据，
     * summary:md5原始数据
     *
     * 也可以先解密再验签 验签失败也可以将被篡改的数据记录下来做分析 可以分析破坏者想干什么
     * @throws Exception
     */
    static void testB() throws Exception {

        // 1.B接收到密文message,使用B的私钥解密message得到明文messageOriginal和数字签名sign
        String messageEncrypted = String.valueOf(map.get("message"));
        // 解码
        byte[] messageBytesEncrypted = RSAUtils.decode(messageEncrypted);
        // 解密
        byte[] messageBytesOriginal = RSAUtils.decryptByPrivateKey(messageBytesEncrypted,privateKeyB);
        String messageOriginal = new String(messageBytesOriginal,"UTF-8");
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
