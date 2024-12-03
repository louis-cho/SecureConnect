package com.secureconnect.security;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
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

    private final ConcurrentHashMap<String, ClientData> client = new ConcurrentHashMap<>();

	private static final long KEY_EXPIRY_TIME = 30 * 60 * 1000;	// 30분

    // private 생성자 (외부에서 인스턴스 생성 불가)
    private SessionCryptoManager() {}

	private void updateAccess(String sessionId) {
		if(client.get(sessionId).getSessionExpiry() != null) {
			client.get(sessionId).setSessionExpiry(System.currentTimeMillis() + KEY_EXPIRY_TIME); // 시간 설정
		}
	}

	private boolean isExpired(String sessionId) {
		Long expiry = client.get(sessionId).getSessionExpiry();
		return expiry == null || System.currentTimeMillis() > expiry;
	}

    // 싱글톤 인스턴스 반환
    public static SessionCryptoManager getInstance() {
        return INSTANCE;
    }

	public void clearExpired() {
		Iterator<Map.Entry<String, ClientData>> iterator = client.entrySet().iterator();
		while(iterator.hasNext()) {
			Map.Entry<String, ClientData> entry = iterator.next();
			String sessionId = entry.getKey();
			if(isExpired(sessionId)) {
				iterator.remove();
			}
		}
	}
    
	public void storeKey(String sessionId, String keyType, SecretKey key) {
		client.computeIfAbsent(sessionId, k -> new ClientData())
				.getKeyStore().put(keyType, key);
		updateAccess(sessionId);
	}
	
	public SecretKey getKey(String sessionId, String keyType) {
		updateAccess(sessionId);
		return client.getOrDefault(sessionId, new ClientData()).getKeyStore().get(keyType);
	}
	
	public void removeKey(String sessionId, String keyType) {
		HashMap<String, SecretKey> sessionKeys = client.get(sessionId).getKeyStore();
		if(sessionKeys != null) {
			sessionKeys.remove(keyType);
			if(sessionKeys.isEmpty()) {
				client.remove(sessionId);
			}
		}
	}
	
	public void removeSession(String sessionId) {
		client.remove(sessionId);
	}
	
	/**
	 * 특정 키 타입의 존재를 확인한다.
	 * @param sessionId
	 * @param keyType
	 * @return
	 */
	public boolean hasKey(String sessionId, String keyType) {
		return client.containsKey(sessionId) && client.get(sessionId).getKeyStore().containsKey(keyType);
	}

	public ClientData getClientData(String sessionId) {
		return client.get(sessionId);
	}

}
