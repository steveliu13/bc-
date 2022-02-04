package com.lyc;

import org.apache.commons.codec.binary.Base64;

public class 国密demo {

    //SM2公钥,hex编码
    public static final String SM2_PUBLIC_KEY="04BD187906B22F246B1BBC3767CBA098A5A86CC134EA4FF6AF1A97AA0C2D7C4A56C1B6DA51605C9D20F2011E5A866E95CB582F54CC4B6BF2535DD87CD547530A64";

    //SM2私钥,hex编码
    public static final String SM2_PRIVATE_KEY="00BA6CE487C2D1715FED04BF54768AE8EA456DDC51DBA55FF963FCBAE13F44EEBF";

    public static void main(String[] args) {
        String plainText = "I love working,一天不上班浑身难受";
        System.out.println("明文:"+plainText);

        System.out.println("============================");

        国密6个方法入口 entrance = new 国密6大方法实现();
        //1. sm2加解密
        byte[] encBytes = entrance.Sm2Encrypt(SM2_PUBLIC_KEY, plainText);
        String base64Enc = Base64.encodeBase64String(encBytes);
        System.out.println("加密结果转base64:"+base64Enc);

        String decText = entrance.Sm2Decrypt(SM2_PRIVATE_KEY, encBytes);
        System.out.println("解密结果:"+decText);

        System.out.println("============================");

        //2. sm2签名验签
        byte[] signBytes = entrance.Sm2Sign(SM2_PRIVATE_KEY, plainText);
        String base64Sign = Base64.encodeBase64String(signBytes);
        System.out.println("签名结果转base64:"+base64Sign);

        boolean result = entrance.Sm2SignValidate(SM2_PUBLIC_KEY, signBytes, plainText);
        System.out.println("验签结果:"+result);

        System.out.println("============================");

        //3. sm4加解密
        String sm4Key = CommonUtil.createSM4Key();
        System.out.println("sm4密钥为:"+sm4Key);
        byte[] sm4EncBytes = entrance.Sm4Encrypt(sm4Key, plainText);
        String sm4base64Enc = Base64.encodeBase64String(sm4EncBytes);
        System.out.println("加密结果转base64:"+sm4base64Enc);

        String sm4DecText = entrance.Sm4Decrypt(sm4Key, sm4EncBytes);
        System.out.println("解密结果:"+sm4DecText);
    }
}
