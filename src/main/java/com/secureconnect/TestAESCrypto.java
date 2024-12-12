package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.generator.sym.AESKeyGenerator;
import com.secureconnect.security.strategy.sym.AESCryptoStrategy;

import javax.crypto.SecretKey;

public class TestAESCrypto {
	  public static void main(String[] args) {
	        try {

				// 세션 매니저 생성
				String sessionId = "akgi04@90df0kgirejlsd";

				String aesPlainText = "AES_TEST_TEXT!";

	            // 1-1. AES 키 생성
				AESKeyGenerator aesKeyGenerator = new AESKeyGenerator();
				aesKeyGenerator.init();
				SecretKey aesKey = aesKeyGenerator.generateKey();


				// 1-2. AES 전략 생성
				AESCryptoStrategy aesCryptoStrategy = new AESCryptoStrategy();
				CryptoChain chain = CryptoChain.getInstance();
				chain.addStrategy(aesCryptoStrategy);
				// 1-3. AES 암호화
				byte[] aesPlainBytes = aesPlainText.getBytes();
				byte[] aesEncryptedBytes = chain.encrypt(aesPlainBytes);

				// 1-4. AES 복호화
				byte[] aesDecryptedBytes = chain.decrypt(aesEncryptedBytes);
				String aesChainResult = new String(aesDecryptedBytes);

				System.out.println(aesChainResult);
				if(aesChainResult.equals(aesPlainText)) {
					System.out.println("AES encrypted successfully");
				}
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
