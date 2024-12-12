package com.secureconnect.security.strategy;

/**
 * 암복호화 파이프라인 구성 요소 관리 인터페이스
 */
public abstract class CryptoStrategy {

	private final String algorithm = null;

	public String getAlgorithm() {
		return algorithm;
	}

	public abstract byte[] encrypt(byte[] data) throws Exception;

	public abstract byte[] decrypt(byte[] data) throws Exception;
}
