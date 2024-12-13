package com.secureconnect.security.strategy.hash;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.HashException;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Message Digest 위변조 검증 클래스
 */
public class MDStrategy extends HashStrategy {

    private final String ALGORITHM;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public MDStrategy() {
        // Properties 파일에서 MD 알고리즘 로드
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.md.algorithm");
    }

    /**
     * 데이터 검증
     * @param data              검증할 데이터
     * @param hash              해시 값
     * @return                  일치 여부
     * @throws HashException    해싱 예외
     */
    @Override
    public boolean verify(byte[] data, byte[] hash) throws HashException {
        byte[] generatedHash = process( data);
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
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new HashException("No such algorithm: " + ALGORITHM, e);
        }
    }
}
