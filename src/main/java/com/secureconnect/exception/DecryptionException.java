package com.secureconnect.exception;

import java.util.logging.Level;
import java.util.logging.Logger;

public class DecryptionException extends CryptoException {
    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(),  "Decryption exception: " + getMessage());
    }
}
