package com.secureconnect.security.strategy.asym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;
import com.secureconnect.exception.NoSuchKeyException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class ECCCryptoStrategy extends AsymCryptoStrategy {

    public static final String PUBLIC_KEY_TYPE = "ECC_PUBLIC";
    public static final String PRIVATE_KEY_TYPE = "ECC_PRIVATE";
    private final String ALGORITHM;
    private final String AES_ALGORITHM;
    private final int AES_KEY_SIZE;

    private final boolean useECDH; // ECDH 또는 ECDSA 모드를 지정

    public ECCCryptoStrategy() {

        ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.ecc.algorithm");
        AES_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.ecc.aes.algorithm");
        AES_KEY_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.ecc.aes.keyLength"));

        if("ECDH".equals(ALGORITHM)) {
            useECDH = true;
        } else {
            useECDH = false;
        }
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (!useECDH) {
            throw new UnsupportedOperationException("ECDH encryption is not available in ECDSA mode.");
        }
        return performECDHEncryption(data);
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (!useECDH) {
            throw new UnsupportedOperationException("ECDH decryption is not available in ECDSA mode.");
        }
        return performECDHDecryption(data);
    }

    public byte[] signData(byte[] data) throws Exception {
        if (useECDH) {
            throw new UnsupportedOperationException("ECDSA signing is not available in ECDH mode.");
        }
        return performECDSASigning(data);
    }

    public boolean verifySignature(byte[] data, byte[] signatureBytes) throws Exception {
        if (useECDH) {
            throw new UnsupportedOperationException("ECDSA verification is not available in ECDH mode.");
        }
        return performECDSAVerification(data, signatureBytes);
    }

    // ============================
    // ECDH 암호화/복호화
    // ============================

    private byte[] performECDHEncryption(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        PublicKey publicKey = super.getKeyPair().getPublic();
        PrivateKey privateKey = super.getKeyPair().getPrivate();

        if (publicKey == null || privateKey == null) {
            throw new NoSuchKeyException("Public or private key not available");
        }

        try {
            // ECDH를 통해 공유 키 생성
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // 공유 키를 사용해 AES 키 생성
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, AES_KEY_SIZE / 8, AES_ALGORITHM);

            // 데이터 암호화
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error during ECDH encryption: " + e.getMessage(), e);
        }
    }

    private byte[] performECDHDecryption(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        PublicKey publicKey = super.getKeyPair().getPublic();
        PrivateKey privateKey = super.getKeyPair().getPrivate();

        if (publicKey == null || privateKey == null) {
            throw new NoSuchKeyException("Public or private key not available");
        }

        try {
            // ECDH를 통해 공유 키 생성
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // 공유 키를 사용해 AES 키 생성
            SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, AES_KEY_SIZE / 8, AES_ALGORITHM);

            // 데이터 복호화
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("Error during ECDH decryption: " + e.getMessage(), e);
        }
    }

    // ============================
    // ECDSA 서명/검증
    // ============================

    private byte[] performECDSASigning(byte[] data) throws Exception {
        PrivateKey privateKey = super.getKeyPair().getPrivate();
        if (privateKey == null) {
            throw new NoSuchKeyException("Private key not available");
        }

        try {
            // 서명 생성
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new EncryptionException("Error during ECDSA signing: " + e.getMessage(), e);
        }
    }

    private boolean performECDSAVerification(byte[] data, byte[] signatureBytes) throws Exception {
        PublicKey publicKey = super.getKeyPair().getPublic();
        if (publicKey == null) {
            throw new NoSuchKeyException("Public key not available");
        }

        try {
            // 서명 검증
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            throw new EncryptionException("Error during ECDSA verification: " + e.getMessage(), e);
        }
    }
}
