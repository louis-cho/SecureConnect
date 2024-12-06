package com.secureconnect.security.strategy.asym;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.secureconnect.exception.DecryptionException;
import com.secureconnect.exception.EncryptionException;
import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.util.KeyUtils;

public class RSACryptoStrategy extends AsymCryptoStrategy {

    private final String PRIVATE_KEY_TYPE = "RSA_PRIVATE";
    private final String PUBLIC_KEY_TYPE = "RSA_PUBLIC";
    private final String ALGORITHM = "RSA";

    public RSACryptoStrategy() {}

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
    	PublicKey publicKey = super.getPublicKey(sessionId, PUBLIC_KEY_TYPE, ALGORITHM);
        if (publicKey == null) {
            throw new EncryptionException("No public key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // 데이터 암호화 (예: AES 키 전송)
        byte[] encryptedKey = cipher.doFinal(data);

        return encryptedKey;
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
    	PrivateKey privateKey = super.getPrivateKey(sessionId, PRIVATE_KEY_TYPE, ALGORITHM);
        if (privateKey == null) {
            throw new DecryptionException("No private key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // RSA로 데이터 복호화
        byte[] decryptedKey = cipher.doFinal(data);

        return decryptedKey;
    }

    @Override
    public PublicKey getPublicKey(String sessionId, String keyType, String algorithm) throws Exception {
        return super.getPublicKey(sessionId, keyType, algorithm);
    }

    @Override
    protected PrivateKey getPrivateKey(String sessionId, String keyType, String algorithm) throws Exception {
        return super.getPrivateKey(sessionId, keyType, algorithm);
    }
}
