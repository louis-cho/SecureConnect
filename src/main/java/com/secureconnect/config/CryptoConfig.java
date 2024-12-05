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

	public Symmetric symmetric;
	public Asymmetric asymmetric;
	public Hash hash;

	private static CryptoConfig INSTANCE = new CryptoConfig();

	public static CryptoConfig getInstance() {
		return INSTANCE;
	}

	private CryptoConfig() {}

	public static class Symmetric {
		public AES AES;
		public DES DES;
		public DES3 DES3;

		public static class AES {
			public String mode;
			public String padding;
			public int keyLength;
			public String iv;
		}

		public static class DES {
			public String mode;
			public String padding;
			public int keyLength;
			public String iv;
		}

		public static class DES3 {
			public String mode;
			public String padding;
			public int keyLength;
			public String iv;
		}
	}

	public static class Asymmetric {
		public RSA RSA;
		public ECC ECC;
		public DH DH;

		public static class RSA {
			public int keyLength;
		}

		public static class ECC {
			public String curve;
		}

		public static class DH {
			public String group;
		}

	}

	public static class Hash {
		public HMAC HMAC;
		public SHA SHA;
		public MD MD;

		public static class HMAC {
			public String hashAlgorithm;
			public String key;
		}

		public static class SHA {
			public String algorithm;
		}
		public static class MD {
			public String algorithm;
		}
	}


	public void loadFromFile(String filePath) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		
		File file = new File(filePath);
		
		if(file.exists() && file.isFile()) {
			INSTANCE = mapper.readValue(file, CryptoConfig.class);			
		}
	}
}
