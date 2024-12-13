package com.secureconnect.security;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;

/**
 * 암복호화와 해시 처리를 위한 체인 구성 클래스
 * 여러 암호화 및 해시 전략을 체인 형태로 관리하고 처리합니다.
 */
public class CryptoChain {

    // 로깅 객체
    private static final Logger logger = Logger.getLogger(CryptoChain.class.getName());

    // 암호화 전략 리스트
    private List<CryptoStrategy> strategies;

    // 해시 처리 전략
    private HashStrategy hashStrategy = null;

    // Singleton 인스턴스
    private static final CryptoChain INSTANCE = new CryptoChain();

    // private 생성자 (싱글톤 패턴 적용)
    private CryptoChain() {
    }

    /**
     * CryptoChain을 초기화합니다.
     *
     * @param strategies 암호화 전략 리스트
     * @param hashStrategy 해시 처리 전략
     */
    public void init(List<CryptoStrategy> strategies, HashStrategy hashStrategy) {
        this.strategies = strategies;
        this.hashStrategy = hashStrategy;
    }

    /**
     * CryptoChain 싱글톤 인스턴스를 반환합니다.
     *
     * @return CryptoChain 인스턴스
     */
    public static CryptoChain getInstance() {
        return INSTANCE;
    }

    /**
     * 암호화 전략을 추가합니다.
     *
     * @param strategy 추가할 암호화 전략
     */
    public void addStrategy(CryptoStrategy strategy) {
        strategies.add(strategy);
    }

    /**
     * 해시 처리 전략을 설정합니다.
     *
     * @param strategy 설정할 해시 처리 전략
     */
    public void addHashStrategy(HashStrategy strategy) {
        this.hashStrategy = strategy;
    }

    /**
     * 현재 설정된 해시 처리 전략을 제거합니다.
     */
    public void removeStrategy() {
        this.hashStrategy = null;
    }

    /**
     * 특정 암호화 전략을 삭제합니다.
     *
     * @param strategyClass 삭제할 암호화 전략의 클래스
     */
    public void removeStrategy(Class<? extends CryptoStrategy> strategyClass) {
        strategies.removeIf(strategy -> strategy.getClass().equals(strategyClass));
    }

    /**
     * 데이터를 검증합니다. 해시 처리 전략이 설정되지 않은 경우 항상 true를 반환합니다.
     *
     * @param data 원본 데이터
     * @param hash 검증할 해시값
     * @return 데이터가 유효하면 true, 그렇지 않으면 false
     * @throws Exception 검증 중 발생한 예외
     */
    public boolean verify(byte[] data, byte[] hash) throws Exception {
        if (hashStrategy == null) {
            return true;
        }
        return hashStrategy.verify(data, hash);
    }

    /**
     * 데이터를 해시 처리합니다.
     *
     * @param data 해시 처리할 데이터
     * @return 해시된 데이터
     * @throws Exception 해시 처리 중 발생한 예외
     */
    public byte[] hash(byte[] data) throws Exception {
        if (hashStrategy == null) {
            return null;
        }
        return hashStrategy.process(data);
    }

    /**
     * 데이터를 암호화합니다. 체인에 추가된 모든 암호화 전략을 순차적으로 적용합니다.
     *
     * @param data 암호화할 데이터
     * @return 암호화된 데이터
     * @throws Exception 암호화 중 발생한 예외
     */
    public byte[] encrypt(byte[] data) throws Exception {
        byte[] result = data;
        for (CryptoStrategy strategy : strategies) {
            result = strategy.encrypt(result);
            logger.info("After Encrypted: " + new String(result));
        }
        return result;
    }

    /**
     * 데이터를 복호화합니다. 체인에 추가된 모든 암호화 전략을 역순으로 적용하여 복호화합니다.
     *
     * @param data 복호화할 데이터
     * @return 복호화된 데이터
     * @throws Exception 복호화 중 발생한 예외
     */
    public byte[] decrypt(byte[] data) throws Exception {
        byte[] result = data;
        for (int i = strategies.size() - 1; i >= 0; i--) { // 역순으로 복호화
            result = strategies.get(i).decrypt(result);
            logger.info("After Decrypted: " + new String(result));
        }
        return result;
    }
}
