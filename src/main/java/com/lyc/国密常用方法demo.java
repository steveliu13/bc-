package com.lyc;

import com.lyc.bo.ByteKeyPair;
import com.lyc.util.CommonUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class 国密常用方法demo {

    //SM2公钥,hex编码
    public static final String SM2_PUBLIC_KEY="04BD187906B22F246B1BBC3767CBA098A5A86CC134EA4FF6AF1A97AA0C2D7C4A56C1B6DA51605C9D20F2011E5A866E95CB582F54CC4B6BF2535DD87CD547530A64";

    //SM2私钥,hex编码
    public static final String SM2_PRIVATE_KEY="00BA6CE487C2D1715FED04BF54768AE8EA456DDC51DBA55FF963FCBAE13F44EEBF";

    public static void main(String[] args) {
        String plainText = "I love working,我爱搬砖";
        System.out.println("明文:"+plainText);

        System.out.println("============================");

        国密常用方法入口 entrance = new 国密常用方法实现();
        //1. 生成一对公私钥
        ByteKeyPair byteKeyPair = entrance.generateSm2KeyPairs();
        //1.1 输出hex格式公私钥
        String hexPublicKey = Hex.encodeHexString(byteKeyPair.getSm2PublicKeyBytes());
        String hexPrivateKey = Hex.encodeHexString(byteKeyPair.getSm2PrivateBytes());
        if(hexPrivateKey.length()>64 && hexPrivateKey.startsWith("00")){
            hexPrivateKey = hexPrivateKey.substring(2);
        }
        System.out.println("hex格式公钥: "+hexPublicKey);
        System.out.println("hex格式私钥: "+hexPrivateKey);
        //1.2 hex格式公私钥转pem格式
        String pemPublicKey = entrance.hexSm2PublicKeyToPem(hexPublicKey);
        String pemPrivateKey = entrance.hexSm2PrivateKeyToPem(hexPrivateKey);
        System.out.println("pem格式公钥: "+pemPublicKey);
        System.out.println("pem格式私钥: "+pemPrivateKey);
        //1.3 pem格式公私钥转回hex格式，比配是否相等
        String hexPublicKeyFromPem = entrance.pemSm2PublicKeyToHex(pemPublicKey);
        String hexPrivateKeyFromPem = entrance.pemSm2PrivateKeyToHex(pemPrivateKey);
        System.out.println("hex格式公钥是否相等： "+hexPublicKey.equals(hexPublicKeyFromPem));
        System.out.println("hex格式私钥是否相等： "+hexPrivateKey.equals(hexPrivateKeyFromPem));
        System.out.println("============================");

        //2. sm2加解密
        byte[] encBytes = entrance.Sm2Encrypt(hexPublicKey, plainText);
        String base64Enc = Base64.encodeBase64String(encBytes);
        System.out.println("加密结果转base64:"+base64Enc);

        String decText = entrance.Sm2Decrypt(hexPrivateKey, encBytes);
        System.out.println("解密结果:"+decText);

        System.out.println("============================");

        //3. sm2签名验签
        byte[] signBytes = entrance.Sm2Sign(hexPrivateKey, plainText);
        String base64Sign = Base64.encodeBase64String(signBytes);
        System.out.println("签名结果转base64:"+base64Sign);

        boolean result = entrance.Sm2SignValidate(hexPublicKey, signBytes, plainText);
        System.out.println("验签结果:"+result);

        System.out.println("============================");

        //4. sm4加解密
        String sm4Key = CommonUtil.createSM4Key();
        System.out.println("sm4密钥为:"+sm4Key);
        byte[] sm4EncBytes = entrance.Sm4Encrypt(sm4Key, plainText);
        String sm4base64Enc = Base64.encodeBase64String(sm4EncBytes);
        System.out.println("加密结果转base64:"+sm4base64Enc);

        String sm4DecText = entrance.Sm4Decrypt(sm4Key, sm4EncBytes);
        System.out.println("解密结果:"+sm4DecText);
    }
}
