package com.secureconnect.security.strategy.asym;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.util.KeyUtils;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class AsymCryptoStrategy extends CryptoStrategy {

    final SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

    @Override
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
        throw new Exception("Encrypt not Implemented");
    }

    @Override
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        throw new Exception("Decrypt not Implemented");
    }

    protected PrivateKey getPrivateKey(String sessionId, String keyType, String algorithm) throws Exception {
        SecretKey key = this.sessionCryptoManager.getKey(sessionId, keyType);
        if(key == null) return null;

        return KeyUtils.toPrivateKey(key, algorithm);
    }

    public PublicKey getPublicKey(String sessionId, String keyType, String algorithm) throws Exception {
        SecretKey key = this.sessionCryptoManager.getKey(sessionId, keyType);
        if(key == null) return null;

        return KeyUtils.toPublicKey(key, algorithm);
    }


}
