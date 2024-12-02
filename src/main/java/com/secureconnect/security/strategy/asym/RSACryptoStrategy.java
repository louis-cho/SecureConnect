package com.secureconnect.security.strategy.asym;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.util.KeyUtils;

public class RSACryptoStrategy implements CryptoStrategy {
    private final SessionCryptoManager sessionManager;
    
    public RSACryptoStrategy() {
        this.sessionManager = SessionCryptoManager.getInstance();
    }

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
    	PublicKey publicKey = getPublicKey(sessionId);
        if (publicKey == null) {
            throw new IllegalStateException("No public key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance("RSA");
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
		
    	PrivateKey privateKey = getPrivateKey(sessionId);
        if (privateKey == null) {
            throw new IllegalStateException("No private key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // RSA로 데이터 복호화
        byte[] decryptedKey = cipher.doFinal(data);

        return decryptedKey;
    }

    // Helper: 세션에서 public key 가져오기
    private PublicKey getPublicKey(String sessionId) throws Exception {
        SecretKey key = sessionManager.getKey(sessionId, "RSA_PUBLIC");
        if (key == null) return null;
        
        return KeyUtils.toPublicKey(key);
    }

    // Helper: 세션에서 private key 가져오기
    private PrivateKey getPrivateKey(String sessionId) throws Exception {
        SecretKey key = sessionManager.getKey(sessionId, "RSA_PRIVATE");
        if (key == null) return null;

        return KeyUtils.toPrivateKey(key);
    }
}
