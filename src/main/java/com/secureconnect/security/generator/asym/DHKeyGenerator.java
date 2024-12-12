package com.secureconnect.security.generator.asym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.CryptoException;
import com.secureconnect.exception.KeyGenerateException;
import com.secureconnect.exception.KeyInitException;

import java.security.*;

/**
 * Diffie Hellman Key Generator
 */
public class DHKeyGenerator implements AsymKeyGenerator {
    private KeyPairGenerator keyPairGenerator;

    /**
     * Diffie Hellman 키 설정 초기화
     * @throws CryptoException
     */
    @Override
    public void init() throws CryptoException {
        int keyLength;
        try {
            keyLength = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.dh.keyLength"));
        } catch (NumberFormatException e) {
            throw new KeyInitException("Invalid Key Length Format: " + e);
        }

        if (keyLength < 1024) {
            throw new KeyInitException("Key length must be at least 1024 bits");
        }

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(keyLength);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyInitException("DH Algorithm not supported: " + e);
        }
    }

    /**
     * Diffie Hellman 키 쌍을 생성한다
     * @return KeyPair
     * @throws CryptoException
     */
    @Override
    public KeyPair generateKeyPair() throws CryptoException {
        if (keyPairGenerator == null) {
            throw new KeyGenerateException("KeyPairGenerator not initialized. Call init() first.");
        }
        return keyPairGenerator.generateKeyPair();
    }
}
