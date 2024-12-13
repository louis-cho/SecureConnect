package com.secureconnect.security.strategy;

/**
 * 암복호화 파이프라인 구성 요소 관리 인터페이스
 * 암호화 및 복호화를 위한 기본 메서드를 정의합니다.
 */
public abstract class CryptoStrategy {

	// 암호화 알고리즘 이름. 하위 클래스에서 설정될 수 있음
	private final String algorithm = null;

	/**
	 * 현재 사용 중인 암호화 알고리즘 이름을 반환합니다.
	 *
	 * @return 암호화 알고리즘 이름
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * 데이터를 암호화합니다.
	 *
	 * @param data 암호화할 데이터
	 * @return 암호화된 데이터
	 * @throws Exception 암호화 중 발생한 예외
	 */
	public abstract byte[] encrypt(byte[] data) throws Exception;

	/**
	 * 데이터를 복호화합니다.
	 *
	 * @param data 복호화할 데이터
	 * @return 복호화된 데이터
	 * @throws Exception 복호화 중 발생한 예외
	 */
	public abstract byte[] decrypt(byte[] data) throws Exception;
}
