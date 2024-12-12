package com.secureconnect.security.strategy;

import com.secureconnect.exception.HashException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HashStrategy {

    protected SecretKey key = null;


    public byte[] process(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash Algorithm Not Supported");
    }

    public boolean verify(byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
        throw new NoSuchAlgorithmException("Hash algorithm not supported");
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }

    public SecretKey getKey() {
        return key;
    }
}
