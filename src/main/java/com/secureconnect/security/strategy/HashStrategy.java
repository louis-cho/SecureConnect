package com.secureconnect.security.strategy;

import com.secureconnect.exception.HashException;
import com.secureconnect.security.SessionCryptoManager;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HashStrategy {

    public final SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

    public byte[] process(String sessionId, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash Algorithm Not Supported");
    }

    public boolean verify(String sessionId, byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash algorithm not supported");
    }
}
