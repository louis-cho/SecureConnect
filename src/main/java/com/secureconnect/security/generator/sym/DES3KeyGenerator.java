package com.secureconnect.security.generator.sym;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class DES3KeyGenerator implements SymKeyGenerator{

    KeyGenerator keyGen;

    @Override
    public void init(int keyLength) throws NoSuchAlgorithmException {
        keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(keyLength);
    }

    @Override
    public SecretKey generateKey() {
        return keyGen.generateKey();
    }
}

