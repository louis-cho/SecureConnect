package com.secureconnect.security;

import com.secureconnect.config.CryptoConfigLoader;
import com.secureconnect.security.generator.asym.RSAKeyGenerator;
import com.secureconnect.security.generator.hash.HMACKeyGenerator;
import com.secureconnect.security.generator.hash.MDKeyGenerator;
import com.secureconnect.security.generator.hash.SHAKeyGenerator;
import com.secureconnect.security.generator.sym.AESKeyGenerator;
import com.secureconnect.security.generator.sym.DESKeyGenerator;
import com.secureconnect.security.generator.sym.DES3KeyGenerator;
import com.secureconnect.security.generator.asym.ECCKeyGenerator;
import com.secureconnect.security.generator.asym.DHKeyGenerator;
import com.secureconnect.security.strategy.CryptoStrategy;
import com.secureconnect.security.strategy.HashStrategy;
import com.secureconnect.security.strategy.asym.DHCryptoStrategy;
import com.secureconnect.security.strategy.asym.ECCCryptoStrategy;
import com.secureconnect.security.strategy.asym.RSACryptoStrategy;
import com.secureconnect.security.strategy.hash.HMACStrategy;
import com.secureconnect.security.strategy.hash.MDStrategy;
import com.secureconnect.security.strategy.hash.SHAStrategy;
import com.secureconnect.security.strategy.sym.AESCryptoStrategy;
import com.secureconnect.security.strategy.sym.DES3CryptoStrategy;
import com.secureconnect.security.strategy.sym.DESCryptoStrategy;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * CryptoChain을 구성하기 위한 빌더 클래스
 * 암호화 및 해시 전략을 생성 및 설정합니다.
 */
public class CryptoChainBuilder {

    // 암호화 전략 리스트
    private List<CryptoStrategy> strategies = new ArrayList<>();

    // 해시 처리 전략
    private HashStrategy hashStrategy = null;

    /**
     * 설정 파일의 순서에 따라 암호화 파이프라인을 생성합니다.
     *
     * @return 생성된 암호화 전략 리스트
     * @throws Exception 암호화 전략 생성 중 발생한 예외
     */
    public List<CryptoStrategy> buildPipeline() throws Exception {
        String sequence = CryptoConfigLoader.getConfigAsMap().get("crypto.sequence");
        if (sequence == null || sequence.isEmpty()) {
            throw new IllegalArgumentException("crypto.sequence is not defined in the configuration.");
        }

        String[] steps = sequence.split(",");
        for (String step : steps) {
            strategies.add(createStrategy(step.trim().toLowerCase()));
        }

        return strategies;
    }

    /**
     * 설정 파일의 정보에 따라 해시 처리 전략을 생성합니다.
     *
     * @return 생성된 해시 처리 전략
     * @throws NoSuchAlgorithmException 지원되지 않는 해시 알고리즘일 경우 발생
     */
    public HashStrategy buildHashStrategy() throws NoSuchAlgorithmException {
        String hash = CryptoConfigLoader.getConfigAsMap().get("crypto.hash");

        if (hash == null || hash.isEmpty()) {
            throw new IllegalArgumentException("crypto.hash is not defined in the configuration.");
        }

        String[] steps = hash.split(",");
        if (steps.length > 0) {
            switch (steps[0].trim().toLowerCase()) {
                case "hmac": {
                    HMACStrategy strategy = new HMACStrategy();
                    HMACKeyGenerator hmacKeyGenerator = new HMACKeyGenerator();
                    hmacKeyGenerator.init();
                    SecretKey hmacKey = hmacKeyGenerator.generateKey();
                    strategy.setKey(hmacKey);
                    return strategy;
                }
                case "sha": {
                    SHAStrategy strategy = new SHAStrategy();
                    SHAKeyGenerator shaKeyGenerator = new SHAKeyGenerator();
                    shaKeyGenerator.init();
                    SecretKey shaKey = shaKeyGenerator.generateKey();
                    strategy.setKey(shaKey);
                    return strategy;
                }
                case "md": {
                    MDStrategy strategy = new MDStrategy();
                    MDKeyGenerator mdKeyGenerator = new MDKeyGenerator();
                    mdKeyGenerator.init();
                    SecretKey mdKey = mdKeyGenerator.generateKey();
                    strategy.setKey(mdKey);
                    return strategy;
                }
                default:
                    throw new IllegalArgumentException("Unsupported hash strategy: " + steps[0]);
            }
        }
        throw new IllegalArgumentException("No valid hash strategy provided in configuration.");
    }

    /**
     * 주어진 단계 이름에 따라 암호화 전략을 생성합니다.
     *
     * @param step 암호화 전략 이름
     * @return 생성된 암호화 전략
     * @throws Exception 암호화 전략 생성 중 발생한 예외
     */
    private CryptoStrategy createStrategy(String step) throws Exception {
        switch (step) {
            case "rsa": {
                RSACryptoStrategy strategy = new RSACryptoStrategy();
                RSAKeyGenerator generator = new RSAKeyGenerator();
                generator.init();
                KeyPair keyPair = generator.generateKeyPair();
                strategy.setKeyPair(keyPair);
                return strategy;
            }

            case "aes": {
                AESCryptoStrategy strategy = new AESCryptoStrategy();
                AESKeyGenerator generator = new AESKeyGenerator();
                generator.init();
                SecretKey secretKey = generator.generateKey();
                strategy.setKey(secretKey);
                return strategy;
            }

            case "des": {
                DESCryptoStrategy strategy = new DESCryptoStrategy();
                DESKeyGenerator generator = new DESKeyGenerator();
                generator.init();
                SecretKey secretKey = generator.generateKey();
                strategy.setKey(secretKey);
                return strategy;
            }

            case "des3": {
                DES3CryptoStrategy strategy = new DES3CryptoStrategy();
                DES3KeyGenerator generator = new DES3KeyGenerator();
                generator.init();
                SecretKey secretKey = generator.generateKey();
                strategy.setKey(secretKey);
                return strategy;
            }

            case "ecc": {
                ECCCryptoStrategy strategy = new ECCCryptoStrategy();
                ECCKeyGenerator generator = new ECCKeyGenerator();
                generator.init();
                KeyPair keyPair = generator.generateKeyPair();
                strategy.setKeyPair(keyPair);
                return strategy;
            }

            case "dh": {
                DHCryptoStrategy strategy = new DHCryptoStrategy();
                DHKeyGenerator generator = new DHKeyGenerator();
                generator.init();
                KeyPair keyPair = generator.generateKeyPair();
                strategy.setKeyPair(keyPair);
                return strategy;
            }

            default:
                throw new IllegalArgumentException("Unsupported step in crypto.sequence: " + step);
        }
    }
}
