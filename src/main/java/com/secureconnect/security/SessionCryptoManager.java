package com.secureconnect.security;

import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

/**
 * 세션 별 암복호화 키 정보를 관리하는 클래스
 * @author wizar
 *
 */
public class SessionCryptoManager {
	
	// 싱글톤 인스턴스
    private static final SessionCryptoManager INSTANCE = new SessionCryptoManager();

    private final ConcurrentHashMap<String, ConcurrentHashMap<String, SecretKey>> keyStore = new ConcurrentHashMap<>();
	
    // private 생성자 (외부에서 인스턴스 생성 불가)
    private SessionCryptoManager() {}
    
    // 싱글톤 인스턴스 반환
    public static SessionCryptoManager getInstance() {
        return INSTANCE;
    }
    
	public void storeKey(String sessionId, String keyType, SecretKey key) {
		keyStore.computeIfAbsent(sessionId, k -> new ConcurrentHashMap<>())
		.put(keyType, key);
	}
	
	public SecretKey getKey(String sessionId, String keyType) {
		return keyStore.getOrDefault(sessionId, new ConcurrentHashMap<>()).get(keyType);
	}
	
	public void removeKey(String sessionId, String keyType) {
		ConcurrentHashMap<String, SecretKey> sessionKeys = keyStore.get(sessionId);
		if(sessionKeys != null) {
			sessionKeys.remove(keyType);
			if(sessionKeys.isEmpty()) {
				keyStore.remove(sessionId);
			}
		}
	}
	
	public void removeSession(String sessionId) {
		keyStore.remove(sessionId);
	}
	
	/**
	 * 특정 키 타입의 존재를 확인한다.
	 * @param sessionId
	 * @param keyType
	 * @return
	 */
	public boolean hasKey(String sessionId, String keyType) {
		return keyStore.containsKey(sessionId) && keyStore.get(sessionId).containsKey(keyType);
	}

}
