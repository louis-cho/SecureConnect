package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class DES3CryptoStrategy extends SymCryptoStrategy {

    public static final String KEY_TYPE = "DES3";
    private final String ALGORITHM;
    private final int IV_SIZE;
    SecretKey des3Key = null;

    public DES3CryptoStrategy() {
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.des3.algorithm");
        IV_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.des3.ivLength"));
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (des3Key == null) {
            throw new EncryptionException("No DES3 key available");
        }

        // IV 생성
        byte[] iv = new byte[IV_SIZE / 8];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, des3Key, ivSpec);

        byte[] encrypted = cipher.doFinal(data);

        // IV와 암호화된 데이터 병합
        return concatenate(iv, encrypted);
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (des3Key == null) {
            throw new EncryptionException("No DES3 key available for session");
        }

        // IV와 암호화된 데이터 분리
        byte[] iv = extractIV(data, IV_SIZE / 8);
        byte[] ciphertext = extractCiphertext(data, IV_SIZE / 8);

        // 복호화
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, des3Key, ivSpec);

        return cipher.doFinal(ciphertext);
    }
}
