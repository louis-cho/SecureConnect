package com.secureconnect;

/**
 * 암호화 모듈 테스트 클래스
 * @author wizar
 *
 */

import com.secureconnect.log.CryptoLog;

public class TestLog {
	  public static void main(String[] args) {
	        try {

				CryptoLog cryptoLog = CryptoLog.getInstance();
				// cryptoLog.getLogger().setLevel(Level.OFF);

				cryptoLog.getLogger().info("Test");
				cryptoLog.getLogger().warning("Test");
				cryptoLog.getLogger().severe("Test");
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
}
