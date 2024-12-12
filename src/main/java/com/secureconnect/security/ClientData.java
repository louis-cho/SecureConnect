package com.secureconnect.security;

import java.security.Key;
import java.util.HashMap;

public class ClientData {
    private HashMap<String, Key> keyStore = null;
    private Long sessionExpiry = null;
    private byte[] sharedSecret = null;

    public ClientData() {
        keyStore = new HashMap<>();
        sessionExpiry = System.currentTimeMillis();
    }

    public HashMap<String, Key> getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(HashMap<String, Key> keyStore) {
        this.keyStore = keyStore;
    }

    public Long getSessionExpiry() {
        return sessionExpiry;
    }

    public void setSessionExpiry(Long sessionExpiry) {
        this.sessionExpiry = sessionExpiry;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }
}
