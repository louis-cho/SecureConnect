package com.secureconnect.security.strategy.sym;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class DESCryptoStrategy extends SymCryptoStrategy {

    private final String DES_ALGORITHM;
    private final int IV_LENGTH;
    private final boolean USE_IV;
    public static final String KEY_TYPE = "DES";
    SecretKey desKey = null;

    public DESCryptoStrategy() {
        // Load algorithm and IV length from properties
        DES_ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.des.algorithm");
        IV_LENGTH = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().getOrDefault("crypto.des.ivLength", "64"));
        USE_IV = DES_ALGORITHM.contains("CBC"); // Determine if IV is needed based on mode
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (desKey == null) {
            throw new EncryptionException("No DES key available");
        }

        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);

        if (USE_IV) {
            byte[] iv = new byte[IV_LENGTH / 8]; // Convert bits to bytes
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, desKey, ivSpec);

            byte[] encrypted = cipher.doFinal(data);
            return concatenate(iv, encrypted);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, desKey);
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }

        if (desKey == null) {
            throw new EncryptionException("No DES key available");
        }

        Cipher cipher = Cipher.getInstance(DES_ALGORITHM);

        if (USE_IV) {
            byte[] iv = extractIV(data, IV_LENGTH / 8); // Extract IV from data
            byte[] ciphertext = extractCiphertext(data, IV_LENGTH / 8); // Extract ciphertext
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, desKey, ivSpec);
            return cipher.doFinal(ciphertext);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            return cipher.doFinal(data);
        }
    }

}
