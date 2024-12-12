package com.secureconnect;

import com.secureconnect.security.strategy.hash.MDStrategy;

import java.util.Base64;

public class TestMDSignature {
    public static void main(String[] args) {
        try {
            // MDStrategy 생성
            MDStrategy mdStrategy = new MDStrategy();

            // 테스트 데이터
            String data = "This is a test message for MD5!";
            byte[] dataBytes = data.getBytes();

            // MD5 해시 생성
            byte[] mdHash = mdStrategy.process(dataBytes);
            String generatedHash = Base64.getEncoder().encodeToString(mdHash);
            System.out.println("Generated MD5 Hash: " + generatedHash);

            // MD5 해시 검증
            boolean isVerified = mdStrategy.verify(dataBytes, mdHash);

            if (isVerified) {
                System.out.println("MD5 Hash verification successful!");
            } else {
                System.out.println("MD5 Hash verification failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
