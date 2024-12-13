package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * Data Encryption Standard 3 암호화 클래스
 */
public class DES3CryptoStrategy extends SymCryptoStrategy {

    private final String ALGORITHM;
    private final int IV_SIZE;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public DES3CryptoStrategy() {
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.des3.algorithm");
        IV_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.des3.ivLength"));
    }

    /**
     * 데이터 암호화
     * @param data          원문 데이터 바이트 배열
     * @return              암호화된 바이트 배열
     * @throws Exception    암호화 도중 발생한 예외
     */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (key == null) {
            throw new EncryptionException("No DES3 key available");
        }

        // IV 생성
        byte[] iv = new byte[IV_SIZE / 8];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 암호화
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] encrypted = cipher.doFinal(data);

        // IV와 암호화된 데이터 병합
        return concatenate(iv, encrypted);
    }

    /**
     * 데이터 복호화
     * @param data          복호화할 데이터
     * @return              복호화된 바이트 배열
     * @throws Exception    복호화 도중 발생한 예외
     */
    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (key == null) {
            throw new EncryptionException("No DES3 key available for session");
        }

        // IV와 암호화된 데이터 분리
        byte[] iv = extractIV(data, IV_SIZE / 8);
        byte[] ciphertext = extractCiphertext(data, IV_SIZE / 8);

        // 복호화
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(ciphertext);
    }
}
