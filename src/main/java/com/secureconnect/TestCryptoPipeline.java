package com.secureconnect;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.secureconnect.config.CryptoConfig;
import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.SessionCryptoManager;
import com.secureconnect.security.strategy.sym.AESCryptoStrategy;
import com.secureconnect.security.strategy.hash.HMACCryptoStrategy;
import com.secureconnect.security.strategy.asym.RSACryptoStrategy;
import com.secureconnect.util.KeyUtils;

public class TestCryptoPipeline {

	public static void main(String[] args) throws IOException {
		
		
		CryptoChain cryptoPipeline = CryptoChain.getInstance();
		CryptoConfig.getInstance().loadFromFile("C:\\Dev\\SecureConnect\\src\\crypto_config.json");
		System.out.println("encryption mode >> " + CryptoConfig.getInstance().asymmetric.RSA.keyLength);
		System.out.println("hmac algorithm >> " + CryptoConfig.getInstance().symmetric.AES.keyLength);
	
		String data = "Hello, World!";
		byte[] byteData = data.getBytes();
		
		String sessionId = "testSessionId";
		try {
			
            // 1. RSA 키 쌍 생성
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(CryptoConfig.getInstance().asymmetric.RSA.keyLength);
            KeyPair keyPair = rsaKeyGen.generateKeyPair();

            // 2. AES 키 생성
            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(CryptoConfig.getInstance().symmetric.AES.keyLength); // AES 키 길이 설정
            SecretKey aesKey = aesKeyGen.generateKey();

            SessionCryptoManager sessionManager = SessionCryptoManager.getInstance();
            sessionManager.storeKey(sessionId, "RSA_PUBLIC", KeyUtils.toSecretKey(keyPair.getPublic()));
            sessionManager.storeKey(sessionId, "RSA_PRIVATE", KeyUtils.toSecretKey(keyPair.getPrivate()));
            sessionManager.storeKey(sessionId, "AES", aesKey);
            sessionManager.storeKey(sessionId, "HMAC", KeyUtils.generateHMACKey(CryptoConfig.getInstance().hash.HMAC.hashAlgorithm));
            
            cryptoPipeline.addStrategy(new RSACryptoStrategy());
            cryptoPipeline.addStrategy(new AESCryptoStrategy());
            cryptoPipeline.addHashStrategy(new HMACCryptoStrategy());
            
            byte[] encrypted = cryptoPipeline.encrypt(byteData, sessionId);
            System.out.println("encrypted >> " + encrypted);
            
            byte[] decrypted = cryptoPipeline.decrypt(encrypted, sessionId);
            String result = new String(decrypted);
            System.out.println("decrypted >> " + result);

            try {

                byte[] hash = cryptoPipeline.hash(sessionId, encrypted);
                boolean verified = cryptoPipeline.verify(sessionId, encrypted, hash);
                System.out.println("verify >> " + verified);
            } catch(Exception e) {
                e.printStackTrace();
            }
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
