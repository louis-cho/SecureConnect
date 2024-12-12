package com.secureconnect.exception;

import java.util.logging.Logger;

/**
 * SecureConnect 커스텀 예외 처리 클래스
 */
public abstract class CryptoException extends Exception {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 예외 후처리 메소드. 각 상세 클래스에서 추가 작성이 가능하다.
     * @param logger
     */
    public abstract void handle(Logger logger);
}
