package com.secureconnect.security.generator.hash;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * 해시 키 생성 인터페이스
 */
public interface HashKeyGenerator {

    /**
     * 설정값 초기화
     * @throws NoSuchAlgorithmException 잘못된 해싱 알고리즘
     */
    void init() throws NoSuchAlgorithmException;

    /**
     * 해싱 키 반환
     * @return SecretKey
     * @throws NoSuchAlgorithmException 잘못된 해싱 알고리즘
     */
    SecretKey generateKey() throws NoSuchAlgorithmException;

    /**
     * 사용된 해싱 알고리즘을 반환한다
     * @return 해시 알고리즘 이름
     */
    String getAlgorithm();
}