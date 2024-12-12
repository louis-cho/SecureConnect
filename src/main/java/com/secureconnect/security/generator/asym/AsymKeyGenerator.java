package com.secureconnect.security.generator.asym;

import com.secureconnect.exception.CryptoException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * 비대칭 암복호화 키 생성 인터페이스
 */
public interface AsymKeyGenerator {

    /**
     * 설정값 초기화
     * @throws CryptoException 키 초기화 과정 중 발생한 예외
     * @throws NoSuchAlgorithmException 잘못된 암호화 알고리즘
     * @throws IOException 설정 프로퍼티 파일 입출력 예외
     */
    void init() throws CryptoException, NoSuchAlgorithmException, IOException;

    /**
     * 암복호화 키 쌍 반환
     * @return KeyPair
     * @throws CryptoException 키 생성 중 발생한 예외
     */
    KeyPair generateKeyPair() throws CryptoException;
}
