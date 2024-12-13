package com.secureconnect.security.strategy.hash;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.HashException;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Secure Hash Algorithm 위변조 검증 클래스
 */
public class SHAStrategy extends HashStrategy {

    private final String ALGORITHM;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public SHAStrategy() {
        // Properties 파일에서 SHA 알고리즘 로드
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.sha.algorithm");
    }

    /**
     * 데이터 검증
     * @param data              해싱할 데이터
     * @param hash              해싱 결과값
     * @return                  일치 여부
     * @throws HashException    해싱 예외
     */
    @Override
    public boolean verify(byte[] data, byte[] hash) throws HashException {
        byte[] generatedHash = process(data);
        if (generatedHash == null) {
            return false;
        }

        return EncodeUtils.getBase64(generatedHash).equals(EncodeUtils.getBase64(hash));
    }

    /**
     * 데이터 해싱
     * @param data              해싱할 데이터
     * @return                  해싱 결과값
     * @throws HashException    해싱 과정 중 발생한 예외
     */
    @Override
    public byte[] process(byte[] data) throws HashException {
        if (data == null) {
            return null;
        }

        try {
            MessageDigest sha = MessageDigest.getInstance(ALGORITHM);
            return sha.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new HashException("No such algorithm: " + ALGORITHM, e);
        }
    }
}
