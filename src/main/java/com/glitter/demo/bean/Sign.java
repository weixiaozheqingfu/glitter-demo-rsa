package com.glitter.demo.bean;

/**
 * Created by Administrator on 2018/4/17.
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
