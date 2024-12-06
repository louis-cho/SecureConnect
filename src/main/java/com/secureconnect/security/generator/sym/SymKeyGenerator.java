package com.secureconnect.security.generator.sym;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public interface SymKeyGenerator {

    void init(int keyLength) throws NoSuchAlgorithmException;
    SecretKey generateKey();
}
