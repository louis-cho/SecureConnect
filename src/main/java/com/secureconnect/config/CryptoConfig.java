package com.secureconnect.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 암호화 모듈 설정값 (키 길이, 알고리즘 등)
 * @author wizar
 *
 */
public class CryptoConfig {

	private String encryptionMode;	// RSA, AES_HMAC, RSA_SHA, COMPLEX
	private int shaLength;
	private int aesKeySize;
	private int rsaKeySize;
	private String hmacAlgorithm;
	private String filePath = null;
	
	private static CryptoConfig INSTANCE = new CryptoConfig();
	
	private CryptoConfig() {}
	
	public static CryptoConfig getInstance() {
		return INSTANCE;	
	}
	
	public String getEncryptionMode() {
		return encryptionMode;
	}
	public int getAesKeySize() {
		return aesKeySize;
	}

	public void setAesKeySize(int aesKeySize) {
		this.aesKeySize = aesKeySize;
	}

	public String getFilePath() {
		return filePath;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public void setEncryptionMode(String encryptionMode) {
		this.encryptionMode = encryptionMode;
	}
	public int getShaLength() {
		return shaLength;
	}
	public void setShaLength(int shaLength) {
		this.shaLength = shaLength;
	}
	
	public int getRsaKeySize() {
		return rsaKeySize;
	}
	public void setRsaKeySize(int rsaKeySize) {
		this.rsaKeySize = rsaKeySize;
	}
	public String getHmacAlgorithm() {
		return hmacAlgorithm;
	}
	public void setHmacAlgorithm(String hmacAlgorithm) {
		this.hmacAlgorithm = hmacAlgorithm;
	}
	
	public void loadFromFile(String filePath) throws IOException {
		this.filePath = filePath;
		ObjectMapper mapper = new ObjectMapper();
		
		File file = new File(filePath);
		
		if(file.exists() && file.isFile()) {
			INSTANCE = mapper.readValue(file, CryptoConfig.class);			
		}
	}
}
