package com.lyc.bo;

public class ByteKeyPair {
    private byte[] sm2PublicKeyBytes;
    private byte[] sm2PrivateBytes;

    public ByteKeyPair(byte[] sm2PublicKeyBytes, byte[] sm2PrivateBytes) {
        this.sm2PublicKeyBytes = sm2PublicKeyBytes;
        this.sm2PrivateBytes = sm2PrivateBytes;
    }


    public byte[] getSm2PublicKeyBytes() {
        return sm2PublicKeyBytes;
    }

    public void setSm2PublicKeyBytes(byte[] sm2PublicKeyBytes) {
        this.sm2PublicKeyBytes = sm2PublicKeyBytes;
    }

    public byte[] getSm2PrivateBytes() {
        return sm2PrivateBytes;
    }

    public void setSm2PrivateBytes(byte[] sm2PrivateBytes) {
        this.sm2PrivateBytes = sm2PrivateBytes;
    }
}
