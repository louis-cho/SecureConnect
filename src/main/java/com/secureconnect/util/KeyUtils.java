package com.secureconnect.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtils {
    public static PublicKey toPublicKey(SecretKey secretKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(secretKey.getEncoded()));
    }

    public static PrivateKey toPrivateKey(SecretKey secretKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(secretKey.getEncoded()));
    }
    
    public static SecretKey generateHMACKey(String algorithm) {
    	KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		
    	keyGen.init(256);
    	return keyGen.generateKey();
    }
    
    public static SecretKeySpec toSecretKey(PublicKey publicKey) {
        return new SecretKeySpec(publicKey.getEncoded(), "RSA");
    }

    public static SecretKeySpec toSecretKey(PrivateKey privateKey) {
        return new SecretKeySpec(privateKey.getEncoded(), "RSA");
    }
}