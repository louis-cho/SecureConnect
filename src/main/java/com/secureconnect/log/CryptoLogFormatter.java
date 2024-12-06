package com.secureconnect.log;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class CryptoLogFormatter extends Formatter {

    @Override
    public String format(LogRecord record) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String timestamp = dateFormat.format(new Date(record.getMillis()));
        return String.format("[%s] %s %s: %s\n", timestamp, record.getLevel(), record.getMessage(), record.getThrown());
    }
}
