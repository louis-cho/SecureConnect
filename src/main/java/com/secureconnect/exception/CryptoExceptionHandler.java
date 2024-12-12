package com.secureconnect.exception;

import com.secureconnect.config.LogConfig;
import com.secureconnect.log.CryptoLog;

import java.util.logging.Logger;

/**
 * CryptoException 발생 시 예외를 처리하기 위한 핸들러
 */
public class CryptoExceptionHandler {

    /**
     * 싱글톤 Logger
     */
    private static final Logger LOGGER = CryptoLog.getInstance().getLogger();

    /**
     * Log 설정값
     */
    public static final LogConfig logConfig = LogConfig.getInstance();

    /**
     * 싱글톤 CryptoExceptionHandler 객체
     */
    public CryptoExceptionHandler INSTANCE = new CryptoExceptionHandler();

    private CryptoExceptionHandler() {}

    /**
     * 핸들러 메소드
     * @param exception CryptoException
     */
    public static void handle(CryptoException exception) {
        exception.handle(LOGGER);
    }
}
