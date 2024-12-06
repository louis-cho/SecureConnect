package com.secureconnect.security.strategy.sym;

import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class DESCryptoStrategy extends SymCryptoStrategy {
    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
       if(data == null) {
           return null;
       }

       SecretKey desKey = sessionCryptoManager.getKey(sessionId, "DES");
       if(desKey == null) {
           throw new EncryptionException("No DES key available for session: " + sessionId);
       }

        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, desKey, ivSpec);

        byte[] encrypted = cipher.doFinal(data);
        return concatenate(iv, encrypted);
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        if (data == null) {
            return null;
        }

        SecretKey desKey = sessionCryptoManager.getKey(sessionId, "DES");
        if(desKey == null) {
            throw new EncryptionException("No DES key available for session: " + sessionId);
        }
        byte[] iv = extractIV(data, 8);
        byte[] ciphertext = extractCiphertext(data, 8);

        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, desKey, ivSpec);

        return cipher.doFinal(ciphertext);
    }
}
