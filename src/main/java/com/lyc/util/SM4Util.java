package com.lyc.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

public class SM4Util {
    private static final String CIPHER_PARAM = "SM4";
    private static final String MODE_PARAM = "SM4/ECB/PKCS7Padding";
    private static final String PROV_NAME = BouncyCastleProvider.PROVIDER_NAME;

    //只需加载一次
    static {
        if (Security.getProperty(PROV_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static Key generateSm4Key(byte[] key) {
        Key sm4Key = new SecretKeySpec(key, CIPHER_PARAM);
        return sm4Key;
    }

    public static byte[] innerSM4Encrypt(byte[] src, byte[] key) throws Exception{
        byte[] dest = null;
        Cipher cipher = Cipher.getInstance(MODE_PARAM, PROV_NAME);
        Key sm4Key = generateSm4Key(key);

        cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        dest = cipher.doFinal(src);
        return dest;
    }

    /**
     * SM4加密入口
     * @param src
     * @param key
     * @return
     * @throws Exception
     */
    public static String sm4Encrypt(String src, String key) throws Exception {
        byte []tempBytes = innerSM4Encrypt(src.getBytes(), key.getBytes());
        return Base64.encodeBase64String(tempBytes);
    }


    /**
     * SM4解密入口
     * @param src byte[]格式密文
     * @param key byte[]格式对称秘钥
     * @return
     * @throws Exception
     */
    public static byte[] innerSM4Decrypt(byte[] key, byte[] src) throws Exception{
        byte[] dest = null;
        Cipher cipher = Cipher.getInstance(MODE_PARAM, PROV_NAME);
        Key sm4Key = generateSm4Key(key);
        cipher.init(Cipher.DECRYPT_MODE, sm4Key);
        dest = cipher.doFinal(src);
        return dest;
    }

}

