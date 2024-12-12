package com.secureconnect.security.generator.sym;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * 대칭키 생성 인터페이스
 */
public interface SymKeyGenerator {

    /**
     * 설정값 초기화
     * @throws NoSuchAlgorithmException 잘못된 해싱 알고리즘
     */
    void init() throws NoSuchAlgorithmException;

    /**
     * 대칭키 반환
     * @return SecretKey
     */
    SecretKey generateKey();
}
