package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class AESCryptoStrategy extends SymCryptoStrategy {

    public static final String KEY_TYPE = "AES";
    private final String ALGORITHM;
    private final int AES_KEY_SIZE;
    private final int IV_SIZE;
    protected SecretKey aesKey = null;

	public AESCryptoStrategy() {
	    ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.aes.algorithm");
        AES_KEY_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.aes.keyLength"));
        IV_SIZE = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.aes.ivLength"));
    }
	
	@Override
    public byte[] encrypt(byte[] data) throws Exception {
		if(data == null) {
			return null;
		}
		
        if (aesKey == null) {
            throw new IllegalStateException("No AES key available");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE/8];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] encrypted = cipher.doFinal(data);
        return concatenate(iv, encrypted);
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
		if(data == null) {
			return null;
		}

        if (aesKey == null) {
            throw new IllegalStateException("No AES key available");
        }

        byte[] iv = extractIV(data, IV_SIZE/8);
        byte[] ciphertext = extractCiphertext(data, IV_SIZE/8);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(AES_KEY_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        return cipher.doFinal(ciphertext);
    }

    public void setKey(SecretKey key) {
        this.aesKey = aesKey;
    }

    public SecretKey getKey() {
        return aesKey;
    }
}
