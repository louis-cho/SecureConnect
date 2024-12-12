package com.secureconnect.log;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * 로그 출력 형태를 정의하는 클래스
 */
public class CryptoLogFormatter extends Formatter {

    /**
     * 로그 출력 형태를 정의한다.
     * @param record 형식을 정의하고 싶은 로그 레코드
     * @return 로그 문자열
     */
    @Override
    public String format(LogRecord record) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String timestamp = dateFormat.format(new Date(record.getMillis()));
        return String.format("[%s] %s %s: %s\n", timestamp, record.getLevel(), record.getMessage(), record.getThrown());
    }
}
