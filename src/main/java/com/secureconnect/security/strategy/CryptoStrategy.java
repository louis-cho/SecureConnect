package com.secureconnect.security.strategy;

/**
 * 암복호화 파이프라인 구성 요소 관리 인터페이스
 */
public abstract class CryptoStrategy {

	public abstract byte[] encrypt(byte[] data, String sessionId) throws Exception;

	public abstract byte[] decrypt(byte[] data, String sessionId) throws Exception;
}
