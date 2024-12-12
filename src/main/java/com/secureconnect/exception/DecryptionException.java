package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * Decrypt 과정 중 발생한 예외 클래스
 */
public class DecryptionException extends CryptoException {

    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Decryption 예외 핸들링
     * @param logger
     */
    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(),  "Decryption exception: " + getMessage());
    }
}
