package com.secureconnect.security.strategy;

import com.secureconnect.security.SessionCryptoManager;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HashStrategy {

    public final SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

    public boolean verify(String sessionId, byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException {
        throw new NoSuchAlgorithmException("Hash algorithm not supported");
    }
}
