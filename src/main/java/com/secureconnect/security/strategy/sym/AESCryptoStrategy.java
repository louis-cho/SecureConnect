package com.secureconnect.security.strategy.sym;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class AESCryptoStrategy extends SymCryptoStrategy {

	public AESCryptoStrategy() {
	}
	
	@Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
		SecretKey aesKey = sessionCryptoManager.getKey(sessionId, "AES");
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
		
    	SecretKey aesKey = sessionCryptoManager.getKey(sessionId, "AES");
        if (aesKey == null) {
            throw new IllegalStateException("No AES key available for session: " + sessionId);
        }

        byte[] iv = extractIV(data, 12);
        byte[] ciphertext = extractCiphertext(data, 12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        return cipher.doFinal(ciphertext);
    }
}
