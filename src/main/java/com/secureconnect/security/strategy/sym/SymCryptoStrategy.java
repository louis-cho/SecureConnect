package com.secureconnect.security.strategy.sym;

import com.secureconnect.security.strategy.CryptoStrategy;

import javax.crypto.SecretKey;

/**
 * 대칭 키 암호화를 위한 기본 전략 클래스
 * 대칭 키 암호화 알고리즘을 구현하기 위한 기본 메서드와 유틸리티 메서드를 제공합니다.
 */
public class SymCryptoStrategy extends CryptoStrategy {

    // 암호화 및 복호화에 사용할 SecretKey
    protected SecretKey key = null;

    /**
     * 데이터를 암호화합니다. 구체적인 구현은 하위 클래스에서 제공합니다.
     *
     * @param data 암호화할 데이터
     * @return 암호화된 데이터
     * @throws Exception 암호화가 구현되지 않은 경우 발생
     */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    /**
     * 데이터를 복호화합니다. 구체적인 구현은 하위 클래스에서 제공합니다.
     *
     * @param data 복호화할 데이터
     * @return 복호화된 데이터
     * @throws Exception 복호화가 구현되지 않은 경우 발생
     */
    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }

    /**
     * 초기화 벡터(IV)와 데이터를 결합합니다.
     *
     * @param iv 초기화 벡터(IV)
     * @param data 결합할 데이터
     * @return IV와 데이터가 결합된 바이트 배열
     */
    protected byte[] concatenate(byte[] iv, byte[] data) {
        byte[] combined = new byte[iv.length + data.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(data, 0, combined, iv.length, data.length);
        return combined;
    }

    /**
     * 데이터에서 초기화 벡터(IV)를 추출합니다.
     *
     * @param data 추출 대상 데이터
     * @param length IV의 길이
     * @return 추출된 IV 바이트 배열
     */
    protected byte[] extractIV(byte[] data, int length) {
        byte[] iv = new byte[length];
        System.arraycopy(data, 0, iv, 0, length);
        return iv;
    }

    /**
     * 데이터에서 암호화된 본문을 추출합니다.
     *
     * @param data 추출 대상 데이터
     * @param srcPos 본문 추출을 시작할 위치
     * @return 추출된 암호화된 본문 바이트 배열
     */
    protected byte[] extractCiphertext(byte[] data, int srcPos) {
        byte[] ciphertext = new byte[data.length - srcPos];
        System.arraycopy(data, srcPos, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }

    /**
     * 암호화 및 복호화에 사용할 SecretKey를 설정합니다.
     *
     * @param key 설정할 SecretKey
     */
    public void setKey(SecretKey key) {
        this.key = key;
    }

    /**
     * 현재 설정된 SecretKey를 반환합니다.
     *
     * @return 설정된 SecretKey
     */
    public SecretKey getKey() {
        return key;
    }
}
