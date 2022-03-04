package com.lyc;

import com.lyc.util.SM2Util;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;


public class SM2密钥转换 {

    /**
     * pem公钥转bc
     * @param pemPublic
     * @return
     */
    public static BCECPublicKey pemPub2Bcec(String pemPublic){
        String hexTemp = pemPub2hex(pemPublic);
        return SM2Util.getECPublicKeyByPublicKeyHex(hexTemp);
    }

    public static String pemPub2hex(String pemPublic){
        String base64PriBytes = pemPublic.replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","").trim();
        byte[] base64temp = Base64.decodeBase64(base64PriBytes);
        return Hex.toHexString(base64temp).substring(52);
    }

    /**
     * pem私钥转bc
     * @param pemPrivate
     * @return
     */
    public static BCECPrivateKey pemPri2Bcec(String pemPrivate){
        String hexTemp = pemPri2hex(pemPrivate);
        return SM2Util.getBCECPrivateKeyByPrivateKeyHex(hexTemp);
    }

    static String pemPri2hex(String pemPrivate){
        String base64PriBytes = pemPrivate.replace("-----BEGIN EC PRIVATE KEY-----","")
                .replace("-----END EC PRIVATE KEY-----","").trim();
        byte[] base64temp = Base64.decodeBase64(base64PriBytes);
        return Hex.toHexString(base64temp).substring(14);
    }

    protected static String hex2PubPem(String hexPublicKey){
        //补充硬加密的头
        String hexHead="3059301306072a8648ce3d020106082a811ccf5501822d034200";
        String hexKey = hexHead+hexPublicKey.replaceAll(" ","");
        //两个拼起来转base64
        String base64Fulfill = Base64.encodeBase64String(Hex.decode(hexKey));
        String sm2PemKey = "-----BEGIN PUBLIC KEY-----"+base64Fulfill+"-----END PUBLIC KEY-----";
        return sm2PemKey;
    }

    protected static String hex2PriPem(String hexPrivateKey){
        //补充硬加密的头
        String hexHead="30250201010420";
        if(hexPrivateKey.length()>64 && hexPrivateKey.startsWith("00")){
            hexPrivateKey = hexPrivateKey.substring(2);
        }
        String hexKey = hexHead+hexPrivateKey.replaceAll(" ","");
        //两个拼起来转base64
        String base64Fulfill = Base64.encodeBase64String(Hex.decode(hexKey));
        String sm2PemKey = "-----BEGIN EC PRIVATE KEY-----"+base64Fulfill+"-----END EC PRIVATE KEY-----";
        return sm2PemKey;
    }

    public static void main(String[] args) throws Exception {
        国密常用方法入口 entrance = new 国密常用方法实现();
        String hexPrivateKey = "f605a60609cb95b6c4783a0948b467189987da3b0028bf7cad0f764ba1519773";
        byte[] encBytes = Hex.decode("3078022034c74d6351ee9d55d9e534a390e754a82eef8df2e1d483aea370d21913d59066022032fe26fafda00a9a2cb2a55e5fbe0351fb1ff8c68e8a1bd8ad5e87912ef4b6c20420833222980fcde758530b82da8c4e16cde9481936f8fdcd8261f6c4ddd955449e0410ff08672a21e9fce56baf5920ef6c167a");
        String decText = entrance.Sm2Decrypt(hexPrivateKey, encBytes);
        System.out.println("解密结果:"+decText);
    }
}
