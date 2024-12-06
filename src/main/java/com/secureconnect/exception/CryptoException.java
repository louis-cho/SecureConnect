package com.secureconnect.exception;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class CryptoException extends Exception {
    public CryptoException(String message) {
        super(message);
    }
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public abstract void handle(Logger logger);
}
