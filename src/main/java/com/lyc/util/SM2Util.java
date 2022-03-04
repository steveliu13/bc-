package com.lyc.util;

import com.lyc.SM2密钥转换;
import com.lyc.bo.ByteKeyPair;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

public class SM2Util {
    public static final int RS_LEN = 32;
    private static final String SIGNATURE_PARAM = "SM3withSM2";
    private static final String PROV_NAME = BouncyCastleProvider.PROVIDER_NAME;
    //SM2曲线名称
    private static final String CURVE_NAME = "sm2p256v1";
    //SM2相关参数
    private static final X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN());

    //椭圆曲线参数规格
    private static final ECParameterSpec ecParameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
    private static final String ALGO_NAME = "EC";


    //只需加载一次
    static {
        if (Security.getProperty(PROV_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * @param publicKeyRaw SM2十六进制公钥
     * @param data         明文数据
     * @return String 十六进制密文
     * @Description 公钥加密
          */
    public static String SM2Encrypt(String publicKeyRaw, String data) throws Exception {
        byte[] arrayOfBytes = innerSM2Encrypt(getECPublicKeyByPublicKeyHex(publicKeyRaw), data, 1);
        //将加密后的字节串转换为十六进制字符串
        return Hex.toHexString(arrayOfBytes);
    }

    public static String SM2EncryptByPemKey(String publicKeyRaw, String data) throws Exception {
        BCECPublicKey bcecPublicKey = SM2密钥转换.pemPub2Bcec(publicKeyRaw);
        byte[] arrayOfBytes = innerSM2Encrypt(bcecPublicKey, data, 1);
        //将加密后的字节串转换为十六进制字符串
        return Hex.toHexString(arrayOfBytes);
    }

    /**
     * @param publicKey SM2公钥
     * @param data      明文数据
     * @param modeType  加密模式
     * @return String
     * @Description 公钥加密
          */
    public static byte[] innerSM2Encrypt(BCECPublicKey publicKey, String data, int modeType) {
        //加密模式
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        //通过公钥对象获取公钥的基本域参数。
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        //通过公钥值和公钥基本参数创建公钥参数对象
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        //根据加密模式实例化SM2公钥加密引擎
        SM2Engine sm2Engine = new SM2Engine(mode);
        //初始化加密引擎
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            //将明文字符串转换为指定编码的字节串
            byte[] in = data.getBytes("utf-8");
            //通过加密引擎对字节数串行加密
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
        } catch (Exception e) {
            System.out.println("SM2加密时出现异常:" + e.getMessage());
            e.printStackTrace();
        }
        return arrayOfBytes;
    }

    /**
     * @param privateKeyRaw SM2十六进制私钥
     * @param cipherData    base64密文数据
     * @return String
     * @Description 私钥解密
          */
    public static String SM2Decrypt(String privateKeyRaw, String cipherData) throws Exception {
        byte[] encBytes = Base64.decodeBase64(cipherData);
//        return new String(innerSM2Decrypt(Hex.decode(privateKeyRaw), encBytes));
        return null;
    }

    public static byte[] innerSM2Decrypt(BCECPrivateKey privateKey, byte[] cipherData, int modeType) throws Exception {
        //解密模式
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1)
            mode = SM2Engine.Mode.C1C2C3;
        //通过私钥对象获取私钥的基本域参数。
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        //通过私钥值和私钥钥基本参数创建私钥参数对象
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
                ecDomainParameters);
        //通过解密模式创建解密引擎并初始化
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        String result = null;
        try {
            //通过解密引擎对密文字节串进行解密
            byte[] arrayOfBytes = sm2Engine.processBlock(cipherData, 0, cipherData.length);
            //将解密后的字节串转换为utf8字符编码的字符串（需要与明文加密时字符串转换成字节串所指定的字符编码保持一致）
            return arrayOfBytes;
        } catch (Exception e) {
            System.out.println("SM2解密时出现异常" + e.getMessage());
        }
        return null;
    }

    private static ECPrivateKeyParameters getPrivateParam(byte[] privateKey) throws Exception{
        BigInteger bigIntD = getBigInteger(privateKey);
        //生成私钥参数
        ECPrivateKeyParameters ecPriParam = new ECPrivateKeyParameters(bigIntD, ecDomainParameters);
        return ecPriParam;
    }


    //椭圆曲线ECParameters ASN.1 结构
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");

    /**
     * @param pubKeyHex 64字节十六进制公钥字符串(如果公钥字符串为65字节首个字节为0x04：表示该公钥为非压缩格式，操作时需要删除)
     * @return BCECPublicKey SM2公钥对象
     * @Description 公钥字符串转换为 BCECPublicKey 公钥对象
          */
    public static BCECPublicKey getECPublicKeyByPublicKeyHex(String pubKeyHex) {
        //截取64字节有效的SM2公钥（如果公钥首个字节为0x04）
        if (pubKeyHex.length() > 128) {
            pubKeyHex = pubKeyHex.substring(pubKeyHex.length() - 128);
        }
        //将公钥拆分为x,y分量（各32字节）
        String stringX = pubKeyHex.substring(0, 64);
        String stringY = pubKeyHex.substring(stringX.length());
        //将公钥x、y分量转换为BigInteger类型
        BigInteger x = new BigInteger(stringX, 16);
        BigInteger y = new BigInteger(stringY, 16);
        //通过公钥x、y分量创建椭圆曲线公钥规范
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(x9ECParameters.getCurve().createPoint(x, y), ecParameterSpec);
        //通过椭圆曲线公钥规范，创建出椭圆曲线公钥对象（可用于SM2加密及验签）
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * @param privateKeyHex 32字节十六进制私钥字符串
     * @return BCECPrivateKey SM2私钥对象
     * @Description 私钥字符串转换为 BCECPrivateKey 私钥对象
          */
    public static BCECPrivateKey getBCECPrivateKeyByPrivateKeyHex(String privateKeyHex) {
        //将十六进制私钥字符串转换为BigInteger对象
        BigInteger d = new BigInteger(privateKeyHex, 16);
        //通过私钥和私钥域参数集创建椭圆曲线私钥规范
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
        //通过椭圆曲线私钥规范，创建出椭圆曲线私钥对象（可用于SM2解密和签名）
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 签名入口
     *
     * @param src    byte[]格式明文
     * @param sm2Key
     * @return
     * @throws Exception
     */
    public static byte[] signature(byte[] src, BCECPrivateKey sm2Key) throws Exception {
        byte[] dest = null;
        Signature signature = Signature.getInstance(SIGNATURE_PARAM, PROV_NAME);
        signature.setParameter(new SM2ParameterSpec("unionpay".getBytes()));
        signature.initSign(sm2Key);
        signature.update(src);
        dest = signature.sign();
        return ans1ToRS(dest);
    }

    /**
     * @param src
     * @param privateKeyRaw
     * @return
     * @throws Exception
     */
    public static String sm2Sign(String src, String privateKeyRaw) throws Exception {
        if (src.isEmpty() || privateKeyRaw == null || privateKeyRaw.length() == 0) {
            throw new Exception("SM2Util_wrong signature input argument illegal!");
        }
        BCECPrivateKey sm2Key = getBCECPrivateKeyByPrivateKeyHex(privateKeyRaw);
        byte[] signResult = signature(src.getBytes(), sm2Key);
        return Base64.encodeBase64String(signResult);

    }

    public static String sm2SignByPemKey(String src, String privateKeyRaw) throws Exception {
        if (src.isEmpty() || privateKeyRaw == null || privateKeyRaw.length() == 0) {
            throw new Exception("SM2Util_wrong signature input argument illegal!");
        }
        BCECPrivateKey sm2Key = SM2密钥转换.pemPri2Bcec(privateKeyRaw);
        byte[] signResult = signature(src.getBytes(), sm2Key);
        return Base64.encodeBase64String(signResult);

    }


    /**
     * @param src          byte[]格式明文
     * @param sign         byte[]格式签名
     * @param sm2Key
     * @return
     * @throws Exception
     */
    public static boolean verifySignature(byte[] src, byte[] sign, BCECPublicKey sm2Key) throws Exception {
        byte[] sign_asn1 = rsPlainByteArrayToAsn1(sign);
        boolean res;
        Signature signature = Signature.getInstance(SIGNATURE_PARAM, PROV_NAME);
        signature.setParameter(new SM2ParameterSpec("unionpay".getBytes()));
        signature.initVerify(sm2Key);
        signature.update(src);
        res = signature.verify(sign_asn1);
        return res;
    }


    private static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) throw new RuntimeException("err rs. ");
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static BigInteger getBigInteger(byte[] privateKey) {
        //将私钥hex字符转化为X值
        BigInteger bigIntD = new BigInteger(privateKey);
        return bigIntD;
    }

    private static byte[] ans1ToRS(byte[] rsDer) {
        ASN1Sequence seq = ASN1Sequence.getInstance(rsDer);
        byte[] r = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    private static byte[] bigIntToFixexLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // r and s are the result of mod n, so they should be less than n and have length<=32
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) return rs;
        else if (rs.length == RS_LEN + 1 && rs[0] == 0) return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("err rs: " + Hex.toHexString(rs));
        }
    }

    private static ECPoint getEcPoint(byte[] publicKey) throws Exception {
        ECPoint ecPoint = parameters.getCurve().decodePoint(publicKey);
        return ecPoint;
    }

    public static String sortMapToSTring(Map<String, String> map) {
        StringBuilder result = new StringBuilder();
        Collection<String> keySet = map.keySet();
        List<String> list = new ArrayList<String>(keySet);
        Collections.sort(list);
        for (int i = 0; i < list.size(); i++) {
            result.append(list.get(i)).append("=").append(map.get(list.get(i))).append("&");
        }
        return result.substring(0, result.length() - 1);
    }

    public static byte[] encrypt(byte[] src, byte[] publicKey) throws Exception{
        if (src == null || publicKey == null || src.length == 0) {
            throw new Exception("SM2Util_wrong encrypt input argument illegal!");
        }
        byte[] dest = null;
        SM2Engine sm2Engine = new SM2Engine();
        ParametersWithRandom ecPubParam = getPublicParam(publicKey);
        sm2Engine.init(true, ecPubParam);
        try {
            dest = sm2Engine.processBlock(src, 0, src.length);
        } catch (InvalidCipherTextException e) {
            throw new Exception("SM2Util_wrong encrypt input src invalid!", e);
        }

        return dest;
    }

    public static byte[] decrypt(byte[] src, byte[] privateKey) throws Exception {
        if (src == null || privateKey == null || src.length == 0 || privateKey.length == 0) {
            throw new Exception("SM2Util_wrong decrypt input argument illegal!");
        }
        byte[] dest = null;
        ECPrivateKeyParameters ecPriParam = getPrivateParam(privateKey);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPriParam);
        try {
            dest = sm2Engine.processBlock(src, 0, src.length);
        } catch (InvalidCipherTextException e) {
            throw new Exception("SM2Util_wrong decrypt input src invalid!", e);
        }
        return dest;
    }

    private static ParametersWithRandom getPublicParam(byte[] publicKey) throws Exception {
        ECPoint ecPoint = getEcPoint(publicKey);
        ECPublicKeyParameters ecPub = new ECPublicKeyParameters(ecPoint, ecDomainParameters);
        ParametersWithRandom ecPubParam = new ParametersWithRandom(ecPub);
        return ecPubParam;
    }


    private static KeyPair generateInnerSm2KeyPair() {
        try {
            final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
            // 获取一个椭圆曲线类型的密钥对生成器
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            SecureRandom random = new SecureRandom();
            // 使用SM2的算法区域初始化密钥生成器
            kpg.initialize(sm2Spec, random);
            // 获取密钥对
            KeyPair keyPair = kpg.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            System.out.println("generate sm2 key pair failed: "+ e.getMessage());
        }
        return null;
    }

    /**
     * 生成byte[]格式sm2公私钥方法入口
     * @return
     */
    public static ByteKeyPair generateSm2Keys(){
        KeyPair sm2KeyPair = generateInnerSm2KeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) sm2KeyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) sm2KeyPair.getPublic();
        byte[]privateKeyBytes = privateKey.getD().toByteArray();
        byte[] tempPrivateBytes = Arrays.copyOfRange(privateKeyBytes,0,privateKeyBytes.length);

        ByteKeyPair result = new ByteKeyPair(publicKey.getQ().getEncoded(false), tempPrivateBytes);
        return result;
    }

    public static void main(String[] args) throws Exception {
//        String publicKeyHex = "048b9993b41ff3f31d2831d5d385e517d27128fac48406ac407431d9ef482c60cd0b93f15da70263b512877166cbbd99229a81d94d67c33fe01c5120833740f9a2";
//        String privateKeyHex = "b43a4bd0fe76b1a623002bf285de60b015f44a282646dd647dae8bb79533b5da";
//        KeyPair keyPair = createECKeyPair();
//        PublicKey publicKey = keyPair.getPublic();
//        if (publicKey instanceof BCECPublicKey) {
//            //获取65字节非压缩缩的十六进制公钥串(0x04)
//            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
//            System.out.println("---->SM2公钥：" + publicKeyHex);
//        }
//        PrivateKey privateKey = keyPair.getPrivate();
//        if (privateKey instanceof BCECPrivateKey) {
//            //获取32字节十六进制私钥串
//            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
//            System.out.println("---->SM2私钥：" + privateKeyHex);
//        }
//        String publicKeyPem = "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEw618p7dYFGbwN0y9TCWfK3/euXCUsAYMtppjKcnAbRa33+TQ+8h+51AhFBpKKmBNQpkAhO+YcK/VTtqI+TSsKw==-----END PUBLIC KEY-----";
//        String privateKeyPem = "-----BEGIN EC PRIVATE KEY-----" +
//                "MCUCAQEEICPBZLQHeFjSCaCQVTsYRCoqRBIFBqhEmwO1UhL+4qe1" +
//                "-----END EC PRIVATE KEY-----";
//        BCECPrivateKey privateKey = SM2pemPrivateKey2BCECKey(privateKeyPem);
//        System.out.println(privateKey.getD());

        /**
         * 公钥加密
         */
//        String data = "=========待加密数据=========";

        //将十六进制公钥串转换为 BCECPublicKey 公钥对象
//        String encryptData = SM2Encrypt(publicKeyPem, data, "pem");
//        System.out.println("---->加密结果：" + encryptData);
//
//        /**
//         * 私钥解密
//         */
        //将十六进制私钥串转换为 BCECPrivateKey 私钥对象
//        data = SM2Decrypt(privateKeyPem, encryptData,"pem");
//        System.out.println("---->解密结果：" + data);
    }


}

