package com.secureconnect.config;


import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

public class CryptoConfigLoader {

	private static final Logger logger = Logger.getLogger(CryptoConfigLoader.class.getName());

	public static Map<String, String> getConfigAsMap() {
		// Load configuration from classpath
		Properties config = new Properties();
		try (InputStream input = CryptoConfigLoader.class.getClassLoader().getResourceAsStream("config.properties")) {
			config.load(input);
		} catch (IOException e) {
			logger.severe("Error when read 'config.properties': " + e.getMessage());
        }

        // Convert Properties to a Map
		Map<String, String> configMap = new HashMap<>();
		for (String key : config.stringPropertyNames()) {
			configMap.put(key, config.getProperty(key));
		}
		return configMap;
	}
}
