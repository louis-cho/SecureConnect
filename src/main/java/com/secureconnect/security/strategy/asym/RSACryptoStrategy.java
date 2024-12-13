package com.secureconnect.security.strategy.asym;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.NoSuchKeyException;

/**
 * RSA 암호화 클래스
 */
public class RSACryptoStrategy extends AsymCryptoStrategy {

    public static final String PRIVATE_KEY_TYPE = "RSA_PRIVATE";
    public static final String PUBLIC_KEY_TYPE = "RSA_PUBLIC";
    private final String ALGORITHM;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public RSACryptoStrategy() {
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.rsa.algorithm");
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
		
    	PublicKey publicKey = super.getKeyPair().getPublic();
        if (publicKey == null) {
            throw new NoSuchKeyException("No public key available");
        }

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("No such algorithm: " + ALGORITHM);
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
		if(data == null) {
			return null;
		}
		
    	PrivateKey privateKey = super.getKeyPair().getPrivate();
        if (privateKey == null) {
            throw new NoSuchKeyException("No private key available");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }




}
