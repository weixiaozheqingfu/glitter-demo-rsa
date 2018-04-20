package com.glitter.demo.util;


import com.glitter.demo.bean.Message;
import com.glitter.demo.bean.Msg;
import com.glitter.demo.bean.Person;
import com.glitter.demo.bean.Sign;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
 * A使用publicKeyB加密data，并使用privateKeyA做数字签名
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
public class RSATester6 {

    static String publicKeyA;
    static String privateKeyA;

    static String publicKeyB;
    static String privateKeyB;

    static String appId = "123";
    static String appSecret = "abc";

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
        String dataJson = gson.toJson(data);

        // 2.对数据进行AES128位对称加密
        String secretKey = UUID.randomUUID().toString();
        String dataEncryptStr = AES128.encrypt(dataJson,secretKey);
        byte[] dataEncryptStrBytes = dataEncryptStr.getBytes("UTF-8");
        String dataEncode = RSAUtils.encode(dataEncryptStrBytes);

        // 3.对数据和秘钥总体做数据摘要
        String summaryStr = DigestUtils.md5Hex(dataJson + secretKey + appId + appSecret);
        byte[] summaryBytes = summaryStr.getBytes("UTF-8");

        // 4.对数据摘要进行私钥签名
        byte[] signBytes = RSAUtils.encryptByPrivateKey(summaryBytes,privateKeyA);
        String signEncode = RSAUtils.encode(signBytes);

        // 5.对对称秘钥和签名进行RSA加密
        Sign signObj = new Sign();
        signObj.setSecretKey(RSAUtils.encode(secretKey.getBytes()));
        signObj.setSign(signEncode);
        String signObjJson = gson.toJson(signObj);

        byte[] signObjBytes = signObjJson.getBytes("UTF-8");
        byte[] signObjBytesEncrypted = RSAUtils.encryptByPublicKey(signObjBytes,publicKeyB);
        String signObjEncode = RSAUtils.encode(signObjBytesEncrypted);

        // 6.将Base64编码信息发送至B
        Message message = new Message();
        message.setData(dataEncode);
        message.setSign(signObjEncode);

        String messageJson = gson.toJson(message);
        byte[] messaggBytes = messageJson.getBytes("UTF-8");
        String messaggEncode = RSAUtils.encode(messaggBytes);

        // 此处仅为演示故将信息放入map中进行数据传递。
        map.put("message",messaggEncode);
    }

    /**
     * 验签解密
     *
     * 也可以先解密再验签 验签失败也可以将被篡改的数据记录下来做分析 可以分析破坏者想干什么
     * @throws Exception
     */
    static void testB() throws Exception {
        // TODO 需要进一步优化注释和代码编排,可参考RSATester5......

        // 1.解码message
        String messageEncode = String.valueOf(map.get("message"));
        byte[] messageDecodeBytes = RSAUtils.decode(messageEncode);
        String messageJson = new String(messageDecodeBytes,"UTF-8");
        Gson gson = new Gson();
        Message message = gson.fromJson(messageJson,Message.class);

        // 2.解码sign,RSA解密signObj,得到对称秘钥secretKey和签名数据sign
        String signObjEncode = message.getSign();
        byte[] signObjDecodeBytes = RSAUtils.decode(signObjEncode);
        byte[] signObjBytes = RSAUtils.decryptByPrivateKey(signObjDecodeBytes,privateKeyB);

        String signObjJson = new String(signObjBytes);
        Sign signObj = gson.fromJson(signObjJson,Sign.class);

        String signEncode = signObj.getSign();
        String secretKeyEncode = signObj.getSecretKey();

        byte[] signDecodeBytes = RSAUtils.decode(signEncode);
        byte[] secretKeyDecodeBytes = RSAUtils.decode(secretKeyEncode);

        String secretKeyStr = new String(secretKeyDecodeBytes,"UTF-8");

        // 3.验签:使用发送者公钥解密sign,能解密成功,得到数据摘要,说明验签第一步成功即消息确实是A发送的。
        byte[] summaryBytes = null;
        String summaryAStr = null;
        try{
            summaryBytes = RSAUtils.decryptByPublicKey(signDecodeBytes,publicKeyA);
            summaryAStr = new String(summaryBytes,"UTF-8");
        }catch (Exception e){
            // TODO 可以触发报警机制...
            throw new Exception("验签失败");
        }

        // 4.解码data,并解密data
        String dataJson = null;
        try{
            String dataEncode = message.getData();
            byte[] dataEncryptStrBytes = RSAUtils.decode(dataEncode);
            String dataEncryptStr = new String(dataEncryptStrBytes);
            dataJson = AES128.decrypt(dataEncryptStr,secretKeyStr);
        }catch (Exception e){
            // TODO 可以触发报警机制...
            throw new Exception("解密失败");
        }

        // 5.接收方拼接数据摘要
        String summaryBStr = DigestUtils.md5Hex(dataJson + secretKeyStr + appId + appSecret);

        // 6.验签第二步，进一步比对信息摘要，验证数据是否被篡改
        try{
            if(!summaryAStr.equals(summaryBStr)){
                throw new Exception("验签失败,数据被篡改");
            }
        }catch (Exception e){
            // TODO 可以触发报警机制...
            throw e;
        }

        // 7.得到数据data可以继续后续业务处理...
        System.out.println("解密结果:"+dataJson);
    }
    
}
