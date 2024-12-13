package com.secureconnect.security.strategy.hash;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.HashException;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC 위변조 검증 클래스
 */
public class HMACStrategy extends HashStrategy {

	private final String ALGORITHM;
	public static final String KEY_TYPE = "HMAC";

	/**
	 * properties로 부터 설정값을 읽어온다
	 */
	public HMACStrategy() {
		// Properties 파일에서 HMAC 알고리즘 로드
		ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.hmac.algorithm");
	}

	/**
	 * 데이터 검증
	 * @param data							검증할 데이터
	 * @param hash							해시 값
	 * @return								일치 여부
	 * @throws NoSuchAlgorithmException		유효하지 않은 알고리즘 예외
	 * @throws InvalidKeyException			유효하지 않은 키 예외
	 * @throws HashException				해싱 예외
	 */
	@Override
	public boolean verify(byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
		byte[] ret = process(data);
		if (ret == null) {
			return false;
		}

		return EncodeUtils.getBase64(ret).equals(EncodeUtils.getBase64(hash));
	}

	/**
	 * 데이터 해싱
	 * @param data						해싱할 데이터
	 * @return							해싱 결과값
	 * @throws HashException			해싱 과정 중 발생한 예외
	 * @throws NoSuchAlgorithmException	유효하지 않은 알고리즘 예외
	 * @throws InvalidKeyException		유효하지 않은 키 예외
	 */
	@Override
	public byte[] process(byte[] data) throws HashException, NoSuchAlgorithmException, InvalidKeyException {
		if (data == null) {
			return null;
		}

		if (key == null) {
			throw new HashException("No HMAC key available");
		}

		Mac mac = Mac.getInstance(ALGORITHM); // 알고리즘 설정값 사용
		mac.init(key);

		return mac.doFinal(data);
	}
}