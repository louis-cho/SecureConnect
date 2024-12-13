package com.secureconnect.config;

import java.io.File;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 로그 모듈 설정값 (콘솔 출력 여부, 로그 레벨 등)
 * @author wizar
 *
 */
public class LogConfig {

    public Log log;

    private static LogConfig INSTANCE = new LogConfig();

    public static LogConfig getInstance() {
        return INSTANCE;
    }

    private LogConfig() {}

    public static class Log {
        public String logLevel;
        public String logPath;
        public boolean fileLog;
        public boolean consoleLog;
    }
}
