package com.secureconnect.security.strategy;

/**
 * 암복호화 파이프라인 구성 요소 관리 인터페이스
 */
public interface CryptoStrategy {

	/**
	 * 암호화를 진행한다
	 * @param data		 	암호화할 데이터
	 * @param sessionId		unique client id
	 * @return				암호화된 바이트 배열을 반환한다
	 * @throws Exception	암호화 과정 중 발생한 예외
	 */
	byte[] encrypt(byte[] data, String sessionId) throws Exception;

	/**
	 * 복호화를 수행한다
	 * @param data 			복호화할 데이터
	 * @param sessionId 	unique client id
	 * @return				복호화된 바이트 배열을 반환한다
	 * @throws Exception	복호화 과정 중 발생한 예외
	 */
	byte[] decrypt(byte[] data, String sessionId) throws Exception;
}
