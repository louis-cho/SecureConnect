package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * Hashing 과정 중 발생한 예외 클래스
 */
public class HashException extends CryptoException {

    public HashException(String message) {
        super(message);
    }

    public HashException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Hash 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Hash exception: " + getMessage());
    }
}
