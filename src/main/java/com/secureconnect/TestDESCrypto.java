package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.generator.sym.DESKeyGenerator;
import com.secureconnect.security.strategy.sym.DESCryptoStrategy;

import javax.crypto.SecretKey;

public class TestDESCrypto {
	  public static void main(String[] args) {
	        try {

				// 세션 매니저 생성
				String sessionId = "akgi04@90df0kgirejlsd";
				SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

				String desPlainText = "DES_TEST_TEXT!";

	            // 1-1. DES 키 생성
				DESKeyGenerator desKeyGenerator = new DESKeyGenerator();
				desKeyGenerator.init(56);
				SecretKey desKey = desKeyGenerator.generateKey();

				sessionCryptoManager.storeKey(sessionId, "DES", desKey);

				// 1-2. DES 전략 생성
				DESCryptoStrategy desCryptoStrategy = new DESCryptoStrategy();
				CryptoChain chain = CryptoChain.getInstance();
				chain.addStrategy(desCryptoStrategy);
				// 1-3. DES 암호화
				byte[] desPlainBytes = desPlainText.getBytes();
				byte[] desEncryptedBytes = chain.encrypt(desPlainBytes, sessionId);

				// 1-4. DES 복호화
				byte[] desDecryptedBytes = chain.decrypt(desEncryptedBytes, sessionId);
				String desChainResult = new String(desDecryptedBytes);

				System.out.println(desChainResult);
				if(desChainResult.equals(desPlainText)) {
					System.out.println("DES decrypted successfully");
				}
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
