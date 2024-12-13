package com.secureconnect.security.strategy;

import com.secureconnect.exception.HashException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 데이터 해싱 및 검증을 위한 전략 클래스
 * 데이터를 해시 처리하고 해시값 검증을 수행하기 위한 기본 메서드를 제공합니다.
 */
public class HashStrategy {

    // 해시 처리에 사용할 SecretKey
    protected SecretKey key = null;

    /**
     * 데이터를 해시 처리합니다. 구체적인 구현은 하위 클래스에서 제공합니다.
     *
     * @param data 해시 처리할 데이터
     * @return 해시된 데이터 바이트 배열
     * @throws NoSuchAlgorithmException 지원되지 않는 해시 알고리즘일 경우 발생
     * @throws InvalidKeyException 유효하지 않은 키가 사용된 경우 발생
     * @throws HashException 기타 해시 처리 중 발생한 예외
     */
    public byte[] process(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash Algorithm Not Supported");
    }

    /**
     * 데이터를 해시 처리한 결과를 검증합니다. 구체적인 구현은 하위 클래스에서 제공합니다.
     *
     * @param data 원본 데이터
     * @param hash 검증할 해시값
     * @return 해시값이 유효한 경우 true, 그렇지 않은 경우 false
     * @throws NoSuchAlgorithmException 지원되지 않는 해시 알고리즘일 경우 발생
     * @throws InvalidKeyException 유효하지 않은 키가 사용된 경우 발생
     * @throws HashException 기타 해시 검증 중 발생한 예외
     */
    public boolean verify(byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash algorithm not supported");
    }

    /**
     * 해시 처리에 사용할 SecretKey를 설정합니다.
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
