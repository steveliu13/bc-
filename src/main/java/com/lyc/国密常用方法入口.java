package com.lyc;

import com.lyc.bo.ByteKeyPair;

public interface 国密常用方法入口 {
    /**
     * sm2加密
     * @param hexPublicKey hex公钥
     * @param plainText 明文
     * @return
     */
    public byte[] Sm2Encrypt(String hexPublicKey, String plainText);

    /**
     * sm2解密
     * @param hexPrivateKey hex私钥
     * @param encBytes 密文
     * @return
     */
    public String Sm2Decrypt(String hexPrivateKey, byte[] encBytes);

    /**
     * sm2签名
     * @param hexPrivateKey hex私钥
     * @param sortedString 待签名内容
     * @return
     */
    public byte[] Sm2Sign(String hexPrivateKey, String sortedString);

    /**
     * sm2验签
     * @param hexPublicKey hex公钥
     * @param value 签名值
     * @param sortedString 待验签内容
     * @return
     */
    public boolean Sm2SignValidate(String hexPublicKey, byte[]  value, String sortedString);

    /**
     * sm4加密
     * @param sm4Key sm4对称秘钥
     * @param plainText 明文
     * @return
     */
    public byte[] Sm4Encrypt(String sm4Key, String plainText);

    /**
     * sm4解密
     * @param sm4Key sm4对称秘钥
     * @param encBytes 密文
     * @return
     */
    public String Sm4Decrypt(String sm4Key, byte[] encBytes);

    /**
     * hex格式sm2公钥转pem
     * @param hexPublicKey hex格式sm2公钥
     * @return
     */
    public String hexSm2PublicKeyToPem(String hexPublicKey);

    /**
     * hex格式sm2私钥转pem
     * @param hexPrivateKey hex格式sm2私钥
     * @return
     */
    public String hexSm2PrivateKeyToPem(String hexPrivateKey);

    /**
     * pem格式sm2公钥转hex
     * @param hexPublicKey pem格式sm2公钥
     * @return
     */
    public String pemSm2PublicKeyToHex(String hexPublicKey);

    /**
     * pem格式sm2私钥转hex
     * @param hexPrivateKey  pem格式sm2私钥
     * @return
     */
    public String pemSm2PrivateKeyToHex(String hexPrivateKey);

    /**
     * 生成一对SM2公私钥
     * @return ByteKeyPair，包含byte[] sm2PublicKeyBytes和byte[] sm2PrivateBytes
     */
    public ByteKeyPair generateSm2KeyPairs();
}
