package com.lyc;

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
        String base64PriBytes = pemPublic.replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","").trim();
        byte[] base64temp = Base64.decodeBase64(base64PriBytes);
        String hexTemp = Hex.toHexString(base64temp).substring(52);
        BCECPublicKey bcecPublicKey= SM2Util.getECPublicKeyByPublicKeyHex(hexTemp);
        return bcecPublicKey;
    }

    /**
     * pem私钥转bc
     * @param pemPrivate
     * @return
     */
    public static BCECPrivateKey pemPri2Bcec(String pemPrivate){
        String base64PriBytes = pemPrivate.replace("-----BEGIN EC PRIVATE KEY-----","")
                .replace("-----END EC PRIVATE KEY-----","").trim();
        byte[] base64temp = Base64.decodeBase64(base64PriBytes);
        String hexTemp = Hex.toHexString(base64temp).substring(14);
        BCECPrivateKey bcecPrivateKey= SM2Util.getBCECPrivateKeyByPrivateKeyHex(hexTemp);
        return bcecPrivateKey;
    }
}
