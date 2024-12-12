package com.secureconnect.log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.logging.*;

public class CryptoLog {

    private static final Logger logger = Logger.getLogger(CryptoLog.class.getName());

    private static final CryptoLog INSTANCE = new CryptoLog();

    private static final String LOG_DIR = "logs";
    private static final String LOG_FILE_PREFIX = "logs/crypto_log_";
    private static final String LOG_FILE_SUFFIX = ".log";

    /**
     * 로그 파일 설정 및 콘솔 출력 설정
     */
    static {
        try {

            // 로그 파일명 설정
            DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
            String currentTime = LocalDateTime.now().format(dateTimeFormatter);
            String logFileName = LOG_FILE_PREFIX + currentTime + LOG_FILE_SUFFIX;

            Files.createDirectories(Paths.get(LOG_DIR));

            // 파일 로그 출력 형식 설정
            FileHandler fileHandler = new FileHandler(logFileName, true);
            fileHandler.setFormatter(new CryptoLogFormatter());
            logger.addHandler(fileHandler);
            fileHandler.setLevel(Level.ALL);

            // 콘솔 로그 출력 형식 설정
            ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setLevel(Level.ALL);
            consoleHandler.setFormatter(new CryptoLogFormatter());
            logger.addHandler(consoleHandler);
            logger.setLevel(Level.ALL);

        } catch(IOException e) {
            System.out.println("Error setting up file handler for logger: " + e.getMessage());
        }
    }

    public CryptoLog() {}

    public static CryptoLog getInstance() {
        return INSTANCE;
    }

    public Logger getLogger() {
        return logger;
    }
}
