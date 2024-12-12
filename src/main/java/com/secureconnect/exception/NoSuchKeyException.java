package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * 키 조회 예외 클래스
 */
public class NoSuchKeyException extends CryptoException {
    
    public NoSuchKeyException(String message) {
        super(message);
    }

    public NoSuchKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * No Such Key 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "No Such Key exception: " + getMessage());
    }
}
