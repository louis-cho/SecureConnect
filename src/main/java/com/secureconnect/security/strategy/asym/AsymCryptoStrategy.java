package com.secureconnect.security.strategy.asym;

import com.secureconnect.security.strategy.CryptoStrategy;

import java.security.KeyPair;

/**
 * 비대칭키 기반 암복호화 클래스
 */
public abstract class AsymCryptoStrategy extends CryptoStrategy {

    protected KeyPair keyPair = null;
    /**
     *
     * @param data
     * @return
     * @throws Exception
     */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }


    public void setKeyPair(KeyPair keyPair) throws Exception {
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
