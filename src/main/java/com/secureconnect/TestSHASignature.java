package com.secureconnect;

import com.secureconnect.security.strategy.hash.SHAStrategy;

import java.util.Base64;

public class TestSHASignature {
    public static void main(String[] args) {
        try {
            // SHAStrategy 생성
            SHAStrategy shaStrategy = new SHAStrategy();

            // 테스트 데이터
            String data = "This is a test message for SHA-256!";
            byte[] dataBytes = data.getBytes();

            // SHA-256 해시 생성
            byte[] shaHash = shaStrategy.process(dataBytes);
            String generatedHash = Base64.getEncoder().encodeToString(shaHash);
            System.out.println("Generated SHA-256 Hash: " + generatedHash);

            // SHA-256 해시 검증
            boolean isVerified = shaStrategy.verify(dataBytes, shaHash);

            if (isVerified) {
                System.out.println("SHA-256 Hash verification successful!");
            } else {
                System.out.println("SHA-256 Hash verification failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
