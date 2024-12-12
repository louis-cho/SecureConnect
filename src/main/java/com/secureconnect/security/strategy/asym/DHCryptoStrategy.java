package com.secureconnect.security.strategy.asym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.DecryptionException;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class DHCryptoStrategy extends AsymCryptoStrategy {

    public static final String PRIVATE_KEY_TYPE = "DH_PRIVATE";
    public static final String PUBLIC_KEY_TYPE = "DH_PUBLIC";
    private final String ALGORITHM;
    private final String AES_ALGORITHM;
    private final String HASH_ALGORITHM;
    private final int AES_KEY_SIZE;

    public DHCryptoStrategy() {
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.algorithm"); // e.g., "DH" or "ECDH"
        AES_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.aes.algorithm"); // e.g., "AES/CBC/PKCS5Padding"
        HASH_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.hash.algorithm"); // e.g., "SHA-256"
        AES_KEY_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.dh.aes.keyLength")); // e.g., 128
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        // Retrieve public and private keys
        PublicKey publicKey = super.getKeyPair().getPublic();
        if (publicKey == null) {
            throw new EncryptionException("No public key available");
        }

        PrivateKey privateKey = super.getKeyPair().getPrivate();

        // Perform key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        // Derive AES key from shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] aesKeyBytes = deriveKey(sharedSecret); // Use dynamic hash algorithm to derive key
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // AES encryption
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] iv = new byte[16]; // IV size is 16 bytes for AES
        new SecureRandom().nextBytes(iv); // Generate random IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] encryptedData = cipher.doFinal(data);

        // Combine IV and encrypted data
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return result;
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        // Retrieve public and private keys
        PrivateKey privateKey = super.getKeyPair().getPrivate();
        PublicKey publicKey = super.getKeyPair().getPublic();

        if (privateKey == null || publicKey == null) {
            throw new DecryptionException("No private or public key available");
        }

        // Perform key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        // Derive AES key from shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] aesKeyBytes = deriveKey(sharedSecret);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // Split IV and encrypted data
        byte[] iv = Arrays.copyOfRange(data, 0, 16); // First 16 bytes are IV
        byte[] encryptedData = Arrays.copyOfRange(data, 16, data.length);

        // AES decryption
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        return cipher.doFinal(encryptedData);
    }

    /**
     * Derive an AES key from the shared secret using a dynamic hash algorithm.
     */
    private byte[] deriveKey(byte[] sharedSecret) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hashedSecret = messageDigest.digest(sharedSecret);
        return Arrays.copyOf(hashedSecret, AES_KEY_SIZE / 8); // Trim to AES key size (e.g., 128 bits)
    }

    @Override
    public void setKeyPair(KeyPair keyPair) throws Exception {
        super.setKeyPair(keyPair);
    }
}
