package com.secureconnect.exception;

import com.secureconnect.config.LogConfig;
import com.secureconnect.log.CryptoLog;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptoExceptionHandler {
    private static final Logger LOGGER = CryptoLog.getInstance().getLogger();

    public static final LogConfig logConfig = LogConfig.getInstance();

    public CryptoExceptionHandler INSTANCE = new CryptoExceptionHandler();

    private CryptoExceptionHandler() {}

    public static void handle(CryptoException exception) {
        exception.handle(LOGGER);
    }
}
