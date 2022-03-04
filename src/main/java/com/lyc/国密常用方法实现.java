package com.lyc;

import com.lyc.bo.ByteKeyPair;
import com.lyc.util.SM2Util;
import com.lyc.util.SM4Util;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

public class 国密常用方法实现 implements 国密常用方法入口 {
    @Override
    public byte[] Sm2Encrypt(String hexPublicKey, String plainText) {
        //生产bc公钥对象
        BCECPublicKey publicKey = SM2Util.getECPublicKeyByPublicKeyHex(hexPublicKey);
        //加密
        try {
            byte[] encText = SM2Util.innerSM2Encrypt(publicKey, plainText,1);
            return encText;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String Sm2Decrypt(String hexPrivateKey, byte[] encBytes) {
        try{
            BCECPrivateKey privateKey = SM2Util.getBCECPrivateKeyByPrivateKeyHex(hexPrivateKey);
            byte[]decResult = SM2Util.innerSM2Decrypt(privateKey, encBytes,1);
            return new String(decResult);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public byte[] Sm2Sign(String hexPrivateKey, String sortedString) {
        try{
            BCECPrivateKey privateKey = SM2Util.getBCECPrivateKeyByPrivateKeyHex(hexPrivateKey);
            byte[]signResult = SM2Util.signature(sortedString.getBytes(), privateKey);
            return signResult;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean Sm2SignValidate(String hexPublicKey, byte[] value, String sortedString) {
        try{
            BCECPublicKey publicKey = SM2Util.getECPublicKeyByPublicKeyHex(hexPublicKey);
            return SM2Util.verifySignature(sortedString.getBytes(), value, publicKey);
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public byte[] Sm4Encrypt(String sm4Key, String plainText) {
        try{
            return SM4Util.innerSM4Encrypt(plainText.getBytes(), sm4Key.getBytes());
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String Sm4Decrypt(String sm4Key, byte[] encBytes) {
        try{
            return new String(SM4Util.innerSM4Decrypt(sm4Key.getBytes(), encBytes));
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String hexSm2PublicKeyToPem(String hexPublicKey) {
        try{
            return SM2密钥转换.hex2PubPem(hexPublicKey);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String hexSm2PrivateKeyToPem(String hexPrivateKey) {
        try{
            return SM2密钥转换.hex2PriPem(hexPrivateKey);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String pemSm2PublicKeyToHex(String hexPublicKey) {
        try{
            return SM2密钥转换.pemPub2hex(hexPublicKey);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String pemSm2PrivateKeyToHex(String hexPrivateKey) {
        try{
            return SM2密钥转换.pemPri2hex(hexPrivateKey);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public ByteKeyPair generateSm2KeyPairs() {
        try{
            ByteKeyPair byteKeyPair =  SM2Util.generateSm2Keys();
            return byteKeyPair;
        }catch (Exception e){
            return null;
        }
    }

}
