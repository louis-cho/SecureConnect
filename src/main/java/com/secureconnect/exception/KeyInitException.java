package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * 키 설정 예외 클래스
 */
public class KeyInitException extends CryptoException{
    public KeyInitException(String message) {
        super(message);
    }

    public KeyInitException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Key Init 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Key Init exception: " + getMessage());
    }
}
