package com.secureconnect.security.strategy.hash;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.HashException;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MDStrategy extends HashStrategy {

    private final String ALGORITHM;

    public MDStrategy() {
        // Properties 파일에서 MD 알고리즘 로드
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.md.algorithm");
    }

    @Override
    public boolean verify(byte[] data, byte[] hash) throws HashException {
        byte[] generatedHash = process( data);
        if (generatedHash == null) {
            return false;
        }

        return EncodeUtils.getBase64(generatedHash).equals(EncodeUtils.getBase64(hash));
    }

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
