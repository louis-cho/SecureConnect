package com.secureconnect.security.generator.hash;

import com.secureconnect.config.CryptoConfigLoader;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC Key Generator
 */
public class HMACKeyGenerator implements HashKeyGenerator {

    private String algorithm;
    private int keySize;

    /**
     * Properties 값을 참고하여 초기화를 진행한다
     * @throws NoSuchAlgorithmException 잘못된 Properties 값으로 인해 발생한 예외
     */
    @Override
    public void init() throws NoSuchAlgorithmException {
        // Properties에서 알고리즘 및 키 길이 로드
        algorithm = CryptoConfigLoader.getConfigAsMap().get("crypto.hmac.algorithm");
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("HMAC algorithm not specified in configuration");
        }

        try {
            keySize = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.hmac.keyLength"));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid HMAC key length specified in configuration");
        }
    }

    /**
     * 해싱 키를 생성한다
     * @return 해시 키 값
     * @throws NoSuchAlgorithmException 부적절한 해싱 알고리즘으로 인한 에외
     */
    @Override
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("Algorithm is not initialized. Call init() first.");
        }

        // 키 생성
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     * HMAC 해싱 알고리즘 반환
     * @return HMAC 해싱 알고리즘 이름 반환
     */
    @Override
    public String getAlgorithm() {
        return algorithm;
    }
}
