package com.secureconnect.security.strategy.asym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;
import com.secureconnect.exception.NoSuchKeyException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

/**
 * Elliptic Curve Cryptograph 암호화 클래스
 */
public class ECCCryptoStrategy extends AsymCryptoStrategy {

    private final String ALGORITHM;
    private final String AES_ALGORITHM;
    private final int AES_KEY_SIZE;

    private final boolean useECDH; // ECDH 또는 ECDSA 모드를 지정

    /**
     * properties로 부터 설정값을 읽어온다
     */
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

    /**
     * 데이터 암호화
     * @param data          암호화할 데이터
     * @return              암호화된 바이트 배열
     * @throws Exception    암호화 도중 발생한 예외
     */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (!useECDH) {
            throw new UnsupportedOperationException("ECDH encryption is not available in ECDSA mode.");
        }
        return performECDHEncryption(data);
    }

    /**
     * 데이터 복호화
     * @param data          복호화할 데이터
     * @return              복호화된 바이트 배열
     * @throws Exception    복호화 도중 발생한 예외
     */
    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (!useECDH) {
            throw new UnsupportedOperationException("ECDH decryption is not available in ECDSA mode.");
        }
        return performECDHDecryption(data);
    }

    /**
     * ECC 서명하기
     * @param data          서명할 데이터
     * @return              서명 결과
     * @throws Exception    서명 도중 발생한 예외
     */
    public byte[] signData(byte[] data) throws Exception {
        if (useECDH) {
            throw new UnsupportedOperationException("ECDSA signing is not available in ECDH mode.");
        }
        return performECDSASigning(data);
    }

    /**
     * ECC 서명 대조하기
     * @param data              서명할 데이터
     * @param signatureBytes    서명 정보
     * @return                  서명 일치 여부
     * @throws Exception        서명 도중 발생한 예외
     */
    public boolean verifySignature(byte[] data, byte[] signatureBytes) throws Exception {
        if (useECDH) {
            throw new UnsupportedOperationException("ECDSA verification is not available in ECDH mode.");
        }
        return performECDSAVerification(data, signatureBytes);
    }

    /**
     * ECDH 암호화
     * @param data          암호화할 데이터
     * @return              암호화된 바이트 배열
     * @throws Exception    암호화 도중 발생한 예외
     */
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

    /**
     * ECDH 복호화
     * @param data          복호화할 데이터
     * @return              복호화된 바이트 배열
     * @throws Exception    복호화 도중 발생한 예외
     */
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

    /**
     * ECDSA 서명
     * @param data          서명할 데이터
     * @return              서명 결과
     * @throws Exception    서명 도중 발생한 예외
     */
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

    /**
     * ECDSA 검증
     * @param data              검증할 데이터
     * @param signatureBytes    서명 데이터
     * @return                  검증 결과
     * @throws Exception        검증 도중 발생한 예외
     */
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
