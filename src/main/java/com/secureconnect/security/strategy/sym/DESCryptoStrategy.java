package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * Data Encryption Standard 암호화 클래스
 */
public class DESCryptoStrategy extends SymCryptoStrategy {

    private final String DES_ALGORITHM;
    private final int IV_LENGTH;
    private final boolean USE_IV;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public DESCryptoStrategy() {
        // Load algorithm and IV length from properties
        DES_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.des.algorithm");
        IV_LENGTH = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().getOrDefault("crypto.des.ivLength", "64"));
        USE_IV = DES_ALGORITHM.contains("CBC"); // Determine if IV is needed based on mode
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
            throw new EncryptionException("No DES key available");
        }

        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);

        if (USE_IV) {
            byte[] iv = new byte[IV_LENGTH / 8]; // Convert bits to bytes
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encrypted = cipher.doFinal(data);
            return concatenate(iv, encrypted);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        }
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
            throw new EncryptionException("No DES key available");
        }

        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);

        if (USE_IV) {
            byte[] iv = extractIV(data, IV_LENGTH / 8); // Extract IV from data
            byte[] ciphertext = extractCiphertext(data, IV_LENGTH / 8); // Extract ciphertext
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return cipher.doFinal(ciphertext);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        }
    }

}
