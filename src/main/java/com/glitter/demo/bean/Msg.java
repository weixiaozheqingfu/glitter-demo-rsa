package com.glitter.demo.bean;

/**
 * Created by Administrator on 2018/4/17.
 */
public class Msg {

    /** 数据 */
    private String data;

    /** 对称秘钥 */
    private String secretKey;

    /** 签名 */
    private String sign;


    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

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
