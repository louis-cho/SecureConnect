package com.secureconnect;

/**
 * 암호화 모듈 테스트 클래스
 * @author wizar
 *
 */

import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.asym.RSACryptoStrategy;
import com.secureconnect.security.strategy.hash.HMACCryptoStrategy;
import com.secureconnect.security.strategy.sym.AESCryptoStrategy;
import com.secureconnect.util.KeyUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class TestHashCrypto {
	  public static void main(String[] args) {
	        try {
	            // 1. RSA 키 쌍 생성
	            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");

				rsaKeyGen.initialize(2048);
	            KeyPair keyPair = rsaKeyGen.generateKeyPair();

	            // 2. AES 키 생성
	            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
	            aesKeyGen.init(128); // AES 키 길이 설정
	            SecretKey aesKey = aesKeyGen.generateKey();

				// 3. HMAC 키 생성
				KeyGenerator hmacKeyGen = KeyGenerator.getInstance("HmacSHA256");
				hmacKeyGen.init(256);
				SecretKey hmacKey = hmacKeyGen.generateKey();

	            // 3. 세션 관리 초기화
	            SessionCryptoManager sessionManager = SessionCryptoManager.getInstance();
	            sessionManager.storeKey("session123", "RSA_PUBLIC", KeyUtils.toSecretKey(keyPair.getPublic()));
	            sessionManager.storeKey("session123", "RSA_PRIVATE", KeyUtils.toSecretKey(keyPair.getPrivate()));
	            sessionManager.storeKey("session123", "AES", aesKey);
				sessionManager.storeKey("session123", "HMAC", hmacKey);

	            // 4. RSA 암호화 전략 생성 및 테스트
	            RSACryptoStrategy rsaStrategy = new RSACryptoStrategy();

	            // AES 키를 RSA로 암호화
	            byte[] encryptedAesKey = rsaStrategy.encrypt(aesKey.getEncoded(), "session123");

	            // AES 키를 RSA로 복호화
	            byte[] decryptedAesKey = rsaStrategy.decrypt(encryptedAesKey, "session123");

	            System.out.println("RSA Encrypted AES Key: " + new String(encryptedAesKey));
	            System.out.println("RSA Decrypted AES Key: " + new String(decryptedAesKey));

	            // 5. AES 암호화 전략 생성 및 테스트
	            AESCryptoStrategy aesStrategy = new AESCryptoStrategy();

	            // 데이터 암호화
	            String originalData = "Sensitive Information";
	            byte[] encryptedData = aesStrategy.encrypt(originalData.getBytes(), "session123");

	            // 데이터 복호화
	            byte[] decryptedData = aesStrategy.decrypt(encryptedData, "session123");

	            System.out.println("Original Data: " + originalData);
	            System.out.println("Decrypted Data: " + new String(decryptedData));

				// 6. HMAC 암호화 전략 생성 및 테스트
				HMACCryptoStrategy hmacCryptoStrategy = new HMACCryptoStrategy();

				byte[] hashed = hmacCryptoStrategy.process("session123", decryptedData);
				boolean verified = hmacCryptoStrategy.verify("session123", decryptedData, hashed);
				if(verified) {
					System.out.println("Successfully verified");
				}
	            // 검증
	            if (originalData.equals(new String(decryptedData))) {
	                System.out.println("RSA to AES Test Success!");
	            } else {
	                System.out.println("RSA to AES Test Fail!");
	            }

	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
