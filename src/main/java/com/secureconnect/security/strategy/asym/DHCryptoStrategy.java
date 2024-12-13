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

/**
 * Diffie Hellman 암호화 클래스
 */
public class DHCryptoStrategy extends AsymCryptoStrategy {

    private final String ALGORITHM;
    private final String AES_ALGORITHM;
    private final String HASH_ALGORITHM;
    private final int AES_KEY_SIZE;
    private byte[] sharedSecret = null;

    /**
     * properties로 부터 설정값을 읽어온다
     */
    public DHCryptoStrategy() {
        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.algorithm"); // e.g., "DH" or "ECDH"
        AES_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.aes.algorithm"); // e.g., "AES/CBC/PKCS5Padding"
        HASH_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.dh.hash.algorithm"); // e.g., "SHA-256"
        AES_KEY_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.dh.aes.keyLength")); // e.g., 128
    }

    /**
     * 데이터 암호화
     * @param data          암호화할 데이터
     * @return              암호화된 byte 배열
     * @throws Exception    암호화 도중 발생한 예외
     */
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
        if(sharedSecret == null) {
            sharedSecret = keyAgreement.generateSecret();
        }
        byte[] aesKeyBytes = deriveKey(sharedSecret); // Use dynamic hash algorithm to derive key
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        // AES encryption
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] iv = new byte[16]; // IV size is 16 bytes for AES
        new SecureRandom().nextBytes(iv); // Generate random IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] encryptedData = cipher.doFinal(data);

        // Combine IV and encrypted data
        byte[] encrypted = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(encryptedData, 0, encrypted, iv.length, encryptedData.length);

        return encrypted;
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
     * 공유 비밀을 사용하여 AES에 호환되는 키를 생성한다
     *
     * @param sharedSecret 공유 비밀
     * @return AES 키 바이트 배열
     * @throws Exception 키 생성 중 발생한 예외
     */
    private byte[] deriveKey(byte[] sharedSecret) throws Exception {
        // MessageDigest 객체를 생성하여 해시 알고리즘을 설정합니다.
        // HASH_ALGORITHM은 SHA-256 또는 다른 해시 알고리즘으로 설정해야 합니다.
        MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);

        // 입력된 sharedSecret(공유 비밀값)을 해시 처리하여 고정 길이의 바이트 배열로 변환합니다.
        byte[] hashedSecret = messageDigest.digest(sharedSecret);

        // 해시 결과를 AES 키 크기(AES_KEY_SIZE)에 맞게 잘라냅니다.
        return Arrays.copyOf(hashedSecret, AES_KEY_SIZE / 8);
    }

}
