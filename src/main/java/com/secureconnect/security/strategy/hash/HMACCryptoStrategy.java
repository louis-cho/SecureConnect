package com.secureconnect.security.strategy.hash;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.util.EncodeUtils;

public class HMACCryptoStrategy extends HashStrategy {

	public HMACCryptoStrategy() {

	}

	@Override
	public boolean verify(String sessionId, byte[] data, byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] ret = process(sessionId, data);
		if(ret == null)
			return false;

		if(EncodeUtils.getBase64(ret).equals(EncodeUtils.getBase64(hash)))
			return true;
		else
			return false;
	}

	public byte[] process(String sessionId, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		if(data == null) {
			return null;
		}

		SecretKey hmacKey = sessionCryptoManager.getKey(sessionId, "HMAC");
		if(hmacKey == null) {
			throw new IllegalStateException("No HMAC key available for session: " + sessionId);
		}

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(hmacKey);

		byte[] ret = mac.doFinal(data);

		return ret;
	}
}
