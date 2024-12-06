package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.generator.sym.DES3KeyGenerator;
import com.secureconnect.security.strategy.sym.DES3CryptoStrategy;

import javax.crypto.SecretKey;

public class TestDES3Crypto {
	  public static void main(String[] args) {
	        try {

				// 세션 매니저 생성
				String sessionId = "akgi04@90df0kgirejlsd";
				SessionCryptoManager sessionCryptoManager = SessionCryptoManager.getInstance();

				String des3PlainText = "1234567890T_TEXT!";

	            // 1-1. DES3 키 생성
				DES3KeyGenerator aesKeyGenerator = new DES3KeyGenerator();
				aesKeyGenerator.init(168);
				SecretKey des3Key = aesKeyGenerator.generateKey();

				sessionCryptoManager.storeKey(sessionId, "DES3", des3Key);

				// 1-2. DES3 전략 생성
				DES3CryptoStrategy des3CryptoStrategy = new DES3CryptoStrategy();
				CryptoChain chain = CryptoChain.getInstance();
				chain.addStrategy(des3CryptoStrategy);
				// 1-3. DES3 암호화
				byte[] des3PlainBytes = des3PlainText.getBytes();
				byte[] des3EncryptedBytes = chain.encrypt(des3PlainBytes, sessionId);

				// 1-4. DES3 복호화
				byte[] des3DecryptedBytes = chain.decrypt(des3EncryptedBytes, sessionId);
				String des3ChainResult = new String(des3DecryptedBytes);

				System.out.println(des3ChainResult);
				if(des3ChainResult.equals(des3PlainText)) {
					System.out.println("DES3 decrypted successfully");
				}
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
