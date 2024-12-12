package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.CryptoChainBuilder;
import com.secureconnect.security.generator.asym.ECCKeyGenerator;
import com.secureconnect.security.generator.asym.RSAKeyGenerator;
import com.secureconnect.security.generator.sym.AESKeyGenerator;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ChainBuilderTest {
	private static final Logger logger = Logger.getLogger(ChainBuilderTest.class.getName());

	static KeyPair rsaKeyPair = null;
	static KeyPair eccKeyPair = null;
	static SecretKey aesKey = null;
	public static void main(String[] args) {
		try {


			initializeSessionKeys();
			// Step 2: Build the pipeline
			CryptoChainBuilder builder = new CryptoChainBuilder();
			List<CryptoStrategy> strategies = builder.buildPipeline();

			HashStrategy hashStrategy = builder.buildHashStrategy();

			// Step 3: Initialize the CryptoChain singleton
			CryptoChain chain = CryptoChain.getInstance();
			chain.init(strategies, hashStrategy);

			// Test data
			String plainText = "This is a test message.";
			logger.info("Original Text: " + plainText);

			// Step 4: Encryption test
			logger.info("Starting encryption...");
			byte[] encryptedData = chain.encrypt(plainText.getBytes());
			logger.info("Encrypted Text: " + new String(encryptedData));

			// Step 5: Decryption test
			logger.info("Starting decryption...");
			byte[] decryptedData = chain.decrypt(encryptedData);
			String decryptedText = new String(decryptedData);
			logger.info("Decrypted Text: " + decryptedText);

			// Step 6: Hash test
			logger.info("Starting hash generation...");
			byte[] hash = chain.hash(plainText.getBytes());
			logger.info("Generated Hash: " + new String(hash));

			// Step 7: Hash verification test
			logger.info("Starting hash verification...");
			boolean isHashValid = chain.verify(plainText.getBytes(), hash);
			logger.info("Hash Verification: " + (isHashValid ? "SUCCESS" : "FAILURE"));

			// Final assertion for validation
			if (!plainText.equals(decryptedText)) {
				logger.severe("Decryption failed: Original and decrypted text do not match.");
			} else {
				logger.info("Encryption and Decryption Test Successful!");
			}

		} catch (Exception e) {
			logger.log(Level.SEVERE, "Error during crypto chain test", e);
		}
	}

	private static void initializeSessionKeys() throws Exception {

		// Generate RSA key pair
		RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator();
		rsaKeyGenerator.init();
		rsaKeyPair = rsaKeyGenerator.generateKeyPair();

		// Generate AES key
		AESKeyGenerator aesKeyGenerator = new AESKeyGenerator();
		aesKeyGenerator.init();
		aesKey = aesKeyGenerator.generateKey();


		ECCKeyGenerator eccKeyGenerator = new ECCKeyGenerator();
		eccKeyGenerator.init();
		eccKeyPair = eccKeyGenerator.generateKeyPair();

	}
}
