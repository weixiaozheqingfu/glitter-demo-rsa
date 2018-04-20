package com.glitter.demo.bean;

/**
 * Created by Administrator on 2018/4/17.
 *
 * 名字虽然叫做Sign其实可以理解为RSA加密数据  和  签名 的载体   最终构建Message中去  就与RSATester4中的结构一致了。
 *
 */
public class Sign {

    /** 对称秘钥 */
    private String secretKey;

    /** 签名 */
    private String sign;


    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

}
