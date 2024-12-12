package com.secureconnect.security.strategy.hash;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.exception.HashException;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACStrategy extends HashStrategy {

	private final String ALGORITHM;
	public static final String KEY_TYPE = "HMAC";

	public HMACStrategy() {
		// Properties 파일에서 HMAC 알고리즘 로드
		ALGORITHM = CryptoConfigLoader.getConfigAsMap().get("crypto.hmac.algorithm");
	}

	@Override
	public boolean verify(byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, HashException {
		byte[] ret = process(data);
		if (ret == null) {
			return false;
		}

		return EncodeUtils.getBase64(ret).equals(EncodeUtils.getBase64(hash));
	}

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