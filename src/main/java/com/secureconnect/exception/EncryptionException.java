package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * Encrypt 과정 중 발생한 예외 클래스
 */
public class EncryptionException extends CryptoException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Encryption 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Encryption exception: " + getMessage());
    }
}
