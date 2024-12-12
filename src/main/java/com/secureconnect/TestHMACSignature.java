package com.secureconnect;

import com.secureconnect.security.generator.hash.HMACKeyGenerator;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.Base64;

public class TestHMACSignature {
    public static void main(String[] args) {
        try {
            // KeyGenerator 초기화 및 키 생성
            HMACKeyGenerator hmacKeyGenerator = new HMACKeyGenerator();
            hmacKeyGenerator.init();
            SecretKey hmacKey = hmacKeyGenerator.generateKey();

            // 테스트 데이터
            String data = "This is a test message for HMAC!";

            // 서명 생성
            Mac mac = Mac.getInstance(hmacKeyGenerator.getAlgorithm());
            mac.init(hmacKey);
            byte[] hmacSignature = mac.doFinal(data.getBytes());
            String encodedSignature = Base64.getEncoder().encodeToString(hmacSignature);
            System.out.println("Generated HMAC Signature: " + encodedSignature);

            // 서명 검증
            mac.init(hmacKey);
            byte[] verification = mac.doFinal(data.getBytes());
            String verificationSignature = Base64.getEncoder().encodeToString(verification);

            if (encodedSignature.equals(verificationSignature)) {
                System.out.println("HMAC Signature verification successful!");
            } else {
                System.out.println("HMAC Signature verification failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
