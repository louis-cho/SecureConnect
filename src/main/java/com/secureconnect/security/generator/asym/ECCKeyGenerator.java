package com.secureconnect.security.generator.asym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.CryptoException;
import com.secureconnect.exception.KeyGenerateException;
import com.secureconnect.exception.KeyInitException;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Elliptic Curve Cryptography Key Generator
 */
public class ECCKeyGenerator implements AsymKeyGenerator {
    private KeyPairGenerator keyPairGenerator;

    /**
     * ECC 키 설정 초기화
     * @throws CryptoException
     */
    @Override
    public void init() throws CryptoException {
        String curveName;
        try {
            curveName = CryptoConfigLoader.getConfigAsMap().get("crypto.ecc.curveName");
            if (curveName == null || curveName.isEmpty()) {
                throw new KeyInitException("Curve name is not specified in configuration");
            }
        } catch (Exception e) {
            throw new KeyInitException("Failed to load ECC curve name from configuration: " + e);
        }

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyInitException("ECC Algorithm not supported: " + e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyInitException("Invalid ECC curve parameters: " + e);
        }
    }

    /**
     * ECC 키 쌍을 생성한다
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
