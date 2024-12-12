package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.generator.asym.RSAKeyGenerator;
import com.secureconnect.security.strategy.asym.RSACryptoStrategy;

import java.security.KeyPair;

public class TestRSACrypto {
	  public static void main(String[] args) {
	        try {

				// 세션 매니저 생성
				String sessionId = "akgi04@90df0kgirejlsd";

				String rsaPlainText = "RSA_TEST_TEXT!";

	            // 1-1. RSA 키 생성
				RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator();
				rsaKeyGenerator.init();
				KeyPair rsaKeyPair = rsaKeyGenerator.generateKeyPair();


				// 1-2. RSA 전략 생성
				RSACryptoStrategy rsaCryptoStrategy = new RSACryptoStrategy();
				CryptoChain chain = CryptoChain.getInstance();
				chain.addStrategy(rsaCryptoStrategy);

				// 1-3. RSA 암호화
				byte[] rsaPlainBytes = rsaPlainText.getBytes();
				byte[] rsaEncryptedBytes = chain.encrypt(rsaPlainBytes);

				// 1-4. RSA 복호화
				byte[] rsaDecryptedBytes = chain.decrypt(rsaEncryptedBytes);
				String rsaChainResult = new String(rsaDecryptedBytes);

				System.out.println(rsaChainResult);
				if(rsaChainResult.equals(rsaPlainText)) {
					System.out.println("RSA encrypted successfully");
				}
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
