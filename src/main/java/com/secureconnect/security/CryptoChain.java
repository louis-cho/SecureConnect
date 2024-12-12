package com.secureconnect.security;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;

public class CryptoChain {

    private static final Logger logger = Logger.getLogger(CryptoChain.class.getName());

    private List<CryptoStrategy> strategies;
    private HashStrategy hashStrategy = null;
    private static final CryptoChain INSTANCE = new CryptoChain();

    private CryptoChain() {
    }

    public void init(List<CryptoStrategy> strategies, HashStrategy hashStrategy) {
        this.strategies = strategies;
        this.hashStrategy = hashStrategy;
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

    public boolean verify(byte[] data, byte[] hash) throws Exception {
        if(hashStrategy == null) {
            return true;
        }
        if(hashStrategy.verify(data, hash)) {
            return true;
        }

        return false;
    }

    public byte[] hash(byte[] data) throws Exception {
        if(hashStrategy == null) {
            return null;
        }
        return hashStrategy.process(data);
    }


    // 암호화
    public byte[] encrypt(byte[] data) throws Exception {
        byte[] result = data;
        for (CryptoStrategy strategy : strategies) {
            result = strategy.encrypt(result);
            logger.info("After Encrypted: " + new String(result));
        }
        return result;
    }

    // 복호화
    public byte[] decrypt(byte[] data) throws Exception {
        byte[] result = data;
        for (int i = strategies.size() - 1; i >= 0; i--) { // 역순으로 복호화
            result = strategies.get(i).decrypt(result);
            logger.info("After Decrypted: " + new String(result));
        }
        return result;
    }
}