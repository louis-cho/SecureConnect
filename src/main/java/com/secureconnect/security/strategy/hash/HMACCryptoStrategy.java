package com.secureconnect.security.strategy.hash;

import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.util.EncodeUtils;

public class HMACCryptoStrategy implements CryptoStrategy {

	private final SessionCryptoManager sessionManager;
			
	private static byte[] lastData = null;
	
	public HMACCryptoStrategy() {
        this.sessionManager = SessionCryptoManager.getInstance();
	}

	/**
	 * 
	 */
	@Override
	public byte[] encrypt(byte[] data, String sessionId) throws Exception {
		if(data == null) {
			return null;
		}
		
		SecretKey hmacKey = sessionManager.getKey(sessionId, "HMAC");
		if (hmacKey == null) {
			throw new IllegalStateException("No HMAC key available for session: " + sessionId);
		}
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(hmacKey);
		
		lastData = data;
		return mac.doFinal(lastData);
	}

	/**
	 * HMAC doesn't support decrypt
	 */
	@Override
	public byte[] decrypt(byte[] data, String sessionId) throws Exception {	
		if(data == null) {
			return null;
		}
		
		SecretKey hmacKey = sessionManager.getKey(sessionId, "HMAC");
		if(hmacKey == null) {
			throw new IllegalStateException("No HMAC key available for session: " + sessionId);
		}
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(hmacKey);
		System.out.println("lastData >> " + Base64.getEncoder().encodeToString(lastData));
		System.out.println("data >> " + Base64.getEncoder().encodeToString(data));
		
		byte[] hmacResult = mac.doFinal(lastData);
		
		if(EncodeUtils.getBase64(hmacResult).equals(EncodeUtils.getBase64(data)))
			return lastData;
		else
			return null;
	}

}
