package com.secureconnect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secureconnect.config.CryptoConfigLoader;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.secureconnect.security.generator.asym.RSAKeyGenerator;
import com.secureconnect.security.generator.sym.AESKeyGenerator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CryptoTestServer {

    static SecretKey aesKey = null;
    static KeyPair rsaKeyPair = null;

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/config", new ConfigHandler());
        server.createContext("/keys", new KeyHandler());
        server.createContext("/decrypt", new DecryptHandler());
        server.createContext("/favicon.ico", exchange -> exchange.sendResponseHeaders(404, -1)); // Ignore favicon
        server.setExecutor(null);
        System.out.println("Server started at http://localhost:8080");
        server.start();
    }

    private static void addCORSHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Access-Control-Max-Age", "3600"); // Cache preflight response
    }

    static class ConfigHandler implements HttpHandler {


        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCORSHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1); // No Content
                return;
            }

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    Map<String, String> config = CryptoConfigLoader.getConfigAsMap();
                    String jsonResponse = new ObjectMapper().writeValueAsString(config);

                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, jsonResponse.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(jsonResponse.getBytes());
                    os.close();
                } catch (Exception e) {
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    static class KeyHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCORSHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1); // No Content
                return;
            }

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    String sessionId = "testSession";

                    // Generate RSA and AES keys
                    RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator();
                    rsaKeyGenerator.init();
                    rsaKeyPair = rsaKeyGenerator.generateKeyPair();

                    AESKeyGenerator aesKeyGenerator = new AESKeyGenerator();
                    aesKeyGenerator.init();
                    aesKey = aesKeyGenerator.generateKey();

                    // Return keys to the client
                    Map<String, String> keys = new HashMap<>();
                    keys.put("RSA_PUBLIC", Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
                    keys.put("AES", Base64.getEncoder().encodeToString(aesKey.getEncoded()));

                    String response = new ObjectMapper().writeValueAsString(keys);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    static class DecryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCORSHeaders(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1); // No Content
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    // JSON 파싱
                    ObjectMapper objectMapper = new ObjectMapper();
                    Map<String, String> json = objectMapper.readValue(exchange.getRequestBody(), Map.class);

                    // IV와 암호화된 데이터를 분리
                    byte[] iv = Base64.getDecoder().decode(json.get("iv"));
                    byte[] encryptedData = Base64.getDecoder().decode(json.get("encrypted"));

                    String sessionId = "testSession";


                    // 복호화
                    byte[] decryptedData = decryptWithAES(encryptedData, iv, aesKey);

                    exchange.getResponseHeaders().add("Content-Type", "text/plain");
                    exchange.sendResponseHeaders(200, decryptedData.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(decryptedData);
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }

        private byte[] decryptWithAES(byte[] encryptedData, byte[] iv, SecretKey aesKey) throws Exception {
            Map<String, String> config = CryptoConfigLoader.getConfigAsMap();
            String aesAlgorithm = config.get("crypto.aes.algorithm");

            Cipher cipher = Cipher.getInstance(aesAlgorithm);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);

            return cipher.doFinal(encryptedData);
        }
    }

}
