package com.secureconnect.security.strategy.sym;

import com.secureconnect.security.strategy.CryptoStrategy;

import javax.crypto.SecretKey;

public class SymCryptoStrategy extends CryptoStrategy {


    protected SecretKey key = null;

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }

    protected byte[] concatenate(byte[] iv, byte[] data) {
        byte[] combined = new byte[iv.length + data.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(data, 0, combined, iv.length, data.length);
        return combined;
    }

    protected byte[] extractIV(byte[] data, int length) {
        byte[] iv = new byte[length];
        System.arraycopy(data, 0, iv, 0, length);
        return iv;
    }

    protected byte[] extractCiphertext(byte[] data, int srcPos) {
        byte[] ciphertext = new byte[data.length - srcPos];
        System.arraycopy(data, srcPos, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }

    public SecretKey getKey() {
        return key;
    }
}
