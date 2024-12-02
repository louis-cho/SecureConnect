package com.secureconnect.security.strategy.sym;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;

public class AESCryptoStrategy implements CryptoStrategy {

	private final SessionCryptoManager sessionManager;
	
	public AESCryptoStrategy() {
		this.sessionManager = SessionCryptoManager.getInstance();
	}
	
	@Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
		SecretKey aesKey = sessionManager.getKey(sessionId, "AES");
        if (aesKey == null) {
            throw new IllegalStateException("No AES key available for session: " + sessionId);
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] encrypted = cipher.doFinal(data);
        return concatenate(iv, encrypted);
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
    	SecretKey aesKey = sessionManager.getKey(sessionId, "AES");
        if (aesKey == null) {
            throw new IllegalStateException("No AES key available for session: " + sessionId);
        }

        byte[] iv = extractIV(data);
        byte[] ciphertext = extractCiphertext(data);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        return cipher.doFinal(ciphertext);
    }

    private byte[] concatenate(byte[] iv, byte[] data) {
        byte[] combined = new byte[iv.length + data.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(data, 0, combined, iv.length, data.length);
        return combined;
    }

    private byte[] extractIV(byte[] data) {
        byte[] iv = new byte[12];
        System.arraycopy(data, 0, iv, 0, 12);
        return iv;
    }

    private byte[] extractCiphertext(byte[] data) {
        byte[] ciphertext = new byte[data.length - 12];
        System.arraycopy(data, 12, ciphertext, 0, ciphertext.length);
        return ciphertext;
    }
}
