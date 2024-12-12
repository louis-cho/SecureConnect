package com.secureconnect;

import com.secureconnect.security.CryptoChain;
import com.secureconnect.security.generator.asym.DHKeyGenerator;
import com.secureconnect.security.strategy.asym.DHCryptoStrategy;

import java.security.KeyPair;

public class TestDHCrypto {
    public static void main(String[] args) {
        try {
            // 세션 매니저 생성
            String sessionId = "session-12345";

            String dhPlainText = "This is a test for DH encryption!";

            // 1. Diffie-Hellman 키 생성
            DHKeyGenerator dhKeyGenerator = new DHKeyGenerator();
            dhKeyGenerator.init();
            KeyPair keyPairA = dhKeyGenerator.generateKeyPair();


            // 2. Diffie-Hellman 암호화 전략 생성
            DHCryptoStrategy dhCryptoStrategy = new DHCryptoStrategy();
            CryptoChain chain = CryptoChain.getInstance();
            chain.addStrategy(dhCryptoStrategy);

            // 3. 암호화
            byte[] plainBytes = dhPlainText.getBytes();
            byte[] encryptedBytes = chain.encrypt(plainBytes);

            // 4. 복호화
            byte[] decryptedBytes = chain.decrypt(encryptedBytes);
            String decryptedText = new String(decryptedBytes);

            // 5. 결과 확인
            System.out.println("Original Text: " + dhPlainText);
            System.out.println("Encrypted Text: " + new String(encryptedBytes));
            System.out.println("Decrypted Text: " + decryptedText);

            if (dhPlainText.equals(decryptedText)) {
                System.out.println("DH Encryption and Decryption Successful!");
            } else {
                System.out.println("DH Encryption and Decryption Failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

