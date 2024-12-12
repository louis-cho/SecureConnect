package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.generator.asym.ECCKeyGenerator;
import com.secureconnect.security.strategy.asym.ECCCryptoStrategy;

import java.security.KeyPair;

public class TestECCCrypto {
	public static void main(String[] args) {
		try {
			// 세션 ID 설정
			String sessionId = "akgi04@90df0kgirejlsd";

			String eccPlainText = "ECC_TEST_TEXT!";

			// 1-1. ECC 키 생성
			ECCKeyGenerator eccKeyGenerator = new ECCKeyGenerator();
			eccKeyGenerator.init();
			KeyPair eccKeyPair = eccKeyGenerator.generateKeyPair();


			// 1-2. ECC 전략 생성
			ECCCryptoStrategy eccCryptoStrategy = new ECCCryptoStrategy();
			CryptoChain chain = CryptoChain.getInstance();
			chain.addStrategy(eccCryptoStrategy);

			// 1-3. ECC 암호화
			byte[] eccPlainBytes = eccPlainText.getBytes();
			byte[] eccEncryptedBytes = chain.encrypt(eccPlainBytes);

			// 1-4. ECC 복호화
			byte[] eccDecryptedBytes = chain.decrypt(eccEncryptedBytes);
			String eccChainResult = new String(eccDecryptedBytes);

			// 결과 확인
			System.out.println(eccChainResult);
			if (eccChainResult.equals(eccPlainText)) {
				System.out.println("ECC encrypted and decrypted successfully");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
