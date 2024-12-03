package com.secureconnect.security.strategy.sym;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SymCryptoStrategy extends CryptoStrategy {

    final SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }
}
