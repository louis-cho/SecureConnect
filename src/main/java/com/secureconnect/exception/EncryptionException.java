package com.secureconnect.exception;

import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptionException extends CryptoException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Encryption exception: " + getMessage());
    }
}
