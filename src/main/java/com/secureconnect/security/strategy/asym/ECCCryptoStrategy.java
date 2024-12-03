package com.secureconnect.security.strategy.asym;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ECCCryptoStrategy extends AsymCryptoStrategy {

    private final String PUBLIC_KEY_TYPE = "ECC_PUBLIC";
    private final String PRIVATE_KEY_TYPE = "ECC_PRIVATE";
    private final String ALGORITHM = "ECIS";

    public ECCCryptoStrategy() {}

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
        if(data == null) {
            return null;
        }

        PublicKey publicKey = super.getPublicKey(sessionId, PUBLIC_KEY_TYPE, ALGORITHM);
        if(publicKey == null) {
            throw new IllegalArgumentException("No public key available for session: " +sessionId);
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        if(data == null) {
            return null;
        }

        PrivateKey privateKey = super.getPrivateKey(sessionId, PRIVATE_KEY_TYPE, ALGORITHM);
        if (privateKey == null) {
            throw new IllegalStateException("No private key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // RSA로 데이터 복호화
        byte[] decryptedKey = cipher.doFinal(data);

        return decryptedKey;
    }

    @Override
    protected PrivateKey getPrivateKey(String sessionId, String keyType, String algorithm) throws Exception {
        return super.getPrivateKey(sessionId, keyType, algorithm);
    }

    @Override
    public PublicKey getPublicKey(String sessionId, String keyType, String algorithm) throws Exception {
        return super.getPublicKey(sessionId, keyType, algorithm);
    }
}
