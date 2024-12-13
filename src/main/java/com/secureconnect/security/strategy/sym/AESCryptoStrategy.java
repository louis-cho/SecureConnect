package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Advanced Encryption Standard 암호화 클래스
 */
public class AESCryptoStrategy extends SymCryptoStrategy {

    private final String ALGORITHM;
    private final int AES_KEY_SIZE;
    private final int IV_SIZE;

    /**
     * properties로 부터 설정값을 읽어온다
     */
	public AESCryptoStrategy() {
	    ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.aes.algorithm");
        AES_KEY_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.aes.keyLength"));
        IV_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.aes.ivLength"));
    }

    /**
     * 데이터 암호화
     * @param data          원문 데이터 바이트 배열
     * @return              암호화된 바이트 배열
     * @throws Exception    암호화 도중 발생한 예외
     */
	@Override
    public byte[] encrypt(byte[] data) throws Exception {
		if(data == null) {
			return null;
		}
		
        if (key == null) {
            throw new IllegalStateException("No AES key available");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE/8];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encrypted = cipher.doFinal(data);
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
		if(data == null) {
			return null;
		}

        if (key == null) {
            throw new IllegalStateException("No AES key available");
        }

        byte[] iv = extractIV(data, IV_SIZE/8);
        byte[] ciphertext = extractCiphertext(data, IV_SIZE/8);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

}
