package com.lyc;

public interface 国密6个方法入口 {
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
}
