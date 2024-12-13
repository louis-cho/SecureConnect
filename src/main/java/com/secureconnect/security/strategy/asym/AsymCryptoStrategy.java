package com.secureconnect.security.strategy.asym;

import com.secureconnect.security.strategy.CryptoStrategy;

import java.security.KeyPair;

/**
 * 비대칭키 기반 암복호화 클래스
 */
public abstract class AsymCryptoStrategy extends CryptoStrategy {

    protected KeyPair keyPair = null;
    /**
     * 데이터 암호화
     * @param data          암호화할 데이터
     * @return Exception
     * @throws Exception    구현 클래스에서 encrypt 메소드를 구현해주세요
     */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    /**
     * 데이터 복호화
     * @param data          복호화할 데이터
     * @return Exception
     * @throws Exception    구현 클래스에서 decrypt 메소드를 구현해주세요
     */
    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }

    /**
     * 공개키, 비밀키 쌍을 설정한다
     * @param keyPair   키페어
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * 공개키, 비밀키 쌍을 반환한다
     * @return  KeyPair
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }
}
