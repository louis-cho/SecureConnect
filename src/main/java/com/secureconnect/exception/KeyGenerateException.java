package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * 키 생성 예외 클래스
 */
public class KeyGenerateException extends CryptoException{
    public KeyGenerateException(String message) {
        super(message);
    }

    public KeyGenerateException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Key Generation 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Key Generation exception: " + getMessage());
    }
}
