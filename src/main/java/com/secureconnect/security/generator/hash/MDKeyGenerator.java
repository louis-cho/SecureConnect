package com.secureconnect.security.generator.hash;

import com.secureconnect.config.CryptoConfigLoader;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * MD Key Generator
 */
public class MDKeyGenerator implements HashKeyGenerator {

    private String algorithm;

    /**
     * Properties 값을 참고하여 초기화를 진행한다
     * @throws NoSuchAlgorithmException
     */
    @Override
    public void init() throws NoSuchAlgorithmException {
        // Properties에서 알고리즘 로드
        algorithm = CryptoConfigLoader.getConfigAsMap().get("crypto.md.algorithm");
        if (algorithm == null || algorithm.isEmpty()) {
            throw new NoSuchAlgorithmException("MD algorithm not specified in configuration");
        }
    }

    /**
     * 해싱 키를 생성한다
     * @return
     * @throws NoSuchAlgorithmException
     */
    @Override
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        // MD는 키가 필요하지 않음
        throw new UnsupportedOperationException("Message Digest (MD) algorithms do not require a key");
    }

    /**
     * MD 해싱 알고리즈마 반환
     * @return MD 해싱 알고리즘 이름 반환
     */
    @Override
    public String getAlgorithm() {
        return algorithm;
    }
}
