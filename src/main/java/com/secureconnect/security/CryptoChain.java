package com.secureconnect.security;

import java.util.ArrayList;
import java.util.List;

import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;

public class CryptoChain {
    private final List<CryptoStrategy> strategies = new ArrayList<>();
    private HashStrategy hashStrategy = null;
    private final SessionCryptoManager sessionManager;
    private static final CryptoChain INSTANCE = new CryptoChain(SessionCryptoManager.getInstance());
    
    private CryptoChain(SessionCryptoManager sessionManager) {
        this.sessionManager = sessionManager;
    }
    
    public static CryptoChain getInstance() {
    	return INSTANCE;
    }

    // 전략 추가
    public void addStrategy(CryptoStrategy strategy) {
        strategies.add(strategy);
    }

    public void addHashStrategy(HashStrategy strategy) {
        this.hashStrategy = strategy;
    }

    public void removeStrategy() {
        this.hashStrategy = null;
    }

    // 전략 삭제
    public void removeStrategy(Class<? extends CryptoStrategy> strategyClass) {
        strategies.removeIf(strategy -> strategy.getClass().equals(strategyClass));
    }

    public boolean verify(String sessionId, byte[] data, byte[] hash) throws Exception {
        if(hashStrategy == null) {
            return true;
        }
        if(hashStrategy.verify(sessionId, data, hash)) {
            return true;
        }

        return false;
    }


    // 암호화
    public byte[] encrypt(byte[] data, String sessionId) throws Exception {
        byte[] result = data;
        for (CryptoStrategy strategy : strategies) {
        	System.out.println("Before Encrypted >> " + result.toString());
            result = strategy.encrypt(result, sessionId);
        	System.out.println("After Encrypted >> " + result.toString() + "\n\n\n");
        }
        return result;
    }

    // 복호화
    public byte[] decrypt(byte[] data, String sessionId) throws Exception {
        byte[] result = data;
        for (int i = strategies.size() - 1; i >= 0; i--) { // 역순으로 복호화
        	System.out.println("Before Decrypted >> " + result.toString());
            result = strategies.get(i).decrypt(result, sessionId);
        	System.out.println("After Decrypted >> " + result.toString());
        }
        return result;
    }
}