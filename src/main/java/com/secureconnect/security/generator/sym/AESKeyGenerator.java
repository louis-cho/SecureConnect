package com.secureconnect.security.generator.sym;

import com.secureconnect.config.CryptoConfigLoader;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * AES Key Generator
 */
public class AESKeyGenerator implements SymKeyGenerator {

    KeyGenerator keyGen;

    /**
     * Properties 값을 참고하여 초기화를 진행한다
     * @throws NoSuchAlgorithmException 잘못된 Properties 값으로 인해 발생한 예외
     */
    @Override
    public void init() throws NoSuchAlgorithmException {
        int keyLength = Integer.parseInt(CryptoConfigLoader.getConfigAsMap().get("crypto.aes.keyLength"));
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyLength);
    }

    /**
     * 대칭키를 생성한다
     * @return 대칭키 값
     */
    @Override
    public SecretKey generateKey() {
        return keyGen.generateKey();
    }
}
