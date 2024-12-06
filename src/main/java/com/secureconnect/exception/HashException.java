package com.secureconnect.exception;

import java.util.logging.Level;
import java.util.logging.Logger;

public class HashException extends CryptoException {
    public HashException(String message) {
        super(message);
    }

    public HashException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public void handle(Logger logger) {
        logger.log(logger.getLevel(), "Hash exception: " + getMessage());
    }
}
