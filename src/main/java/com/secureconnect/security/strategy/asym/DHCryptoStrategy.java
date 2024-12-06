package com.secureconnect.security.strategy.asym;

import com.secureconnect.exception.DecryptionException;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

public class DHCryptoStrategy extends AsymCryptoStrategy {

    private final String PRIVATE_KEY_TYPE = "DH_PRIVATE";
    private final String PUBLIC_KEY_TYPE = "DH_PUBLIC";
    private final String ALGORITHM = "DH";

    public DHCryptoStrategy() {

    }

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
        if(data == null) {
            return null;
        }

        PublicKey publicKey = super.getPublicKey(sessionId, PUBLIC_KEY_TYPE, ALGORITHM);
        if (publicKey == null) {
            throw new EncryptionException("No public key available for session: " + sessionId);
        }

        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(super.getPrivateKey(sessionId, PRIVATE_KEY_TYPE, ALGORITHM));
        keyAgreement.doPhase(publicKey, true);

        byte[] sharedSecret = sessionCryptoManager.getClientData(sessionId).getSharedSecret();
        if(sharedSecret == null) {
            sharedSecret = keyAgreement.generateSecret();
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] encryptedData = cipher.doFinal(data);

        byte[] result = Arrays.copyOf(encryptedData, encryptedData.length + iv.length);
        System.arraycopy(iv, 0, result, encryptedData.length, iv.length);
        System.arraycopy(iv, 0, result, encryptedData.length + iv.length, iv.length);

        return result;
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        if(data == null) {
            return null;
        }

        PrivateKey privateKey = super.getPrivateKey(sessionId, PRIVATE_KEY_TYPE, ALGORITHM);
        if(privateKey == null) {
            throw new DecryptionException("No public key available for session: " + sessionId);
        }

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(super.getPrivateKey(sessionId, PRIVATE_KEY_TYPE, ALGORITHM));
        keyAgreement.doPhase(privateKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();

        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = Arrays.copyOfRange(data, 0,16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        byte[] encryptedData = Arrays.copyOfRange(data, 16,data.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(encryptedData);
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
