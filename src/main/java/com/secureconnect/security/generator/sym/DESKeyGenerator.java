package com.secureconnect.security.generator.sym;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class DESKeyGenerator implements SymKeyGenerator{

    KeyGenerator keyGen;

    @Override
    public void init(int keyLength) throws NoSuchAlgorithmException {
        keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(keyLength);
    }

    @Override
    public SecretKey generateKey() {
        return keyGen.generateKey();
    }
}
