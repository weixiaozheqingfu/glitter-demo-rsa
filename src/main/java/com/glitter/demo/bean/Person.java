package com.glitter.demo.bean;

/**
 * Created by Administrator on 2018/4/17.
 */
public class Person {

    /** 姓名 */
    private String name;

    /** 性别 */
    private Byte sex;

    /** 年龄 */
    private Integer age;

    /** 身份证号 */
    private String idNumber;


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Byte getSex() {
        return sex;
    }

    public void setSex(Byte sex) {
        this.sex = sex;
    }

    public Integer getAge() {
        return age;
    }

    public void setAge(Integer age) {
        this.age = age;
    }

    public String getIdNumber() {
        return idNumber;
    }

    public void setIdNumber(String idNumber) {
        this.idNumber = idNumber;
    }

}
