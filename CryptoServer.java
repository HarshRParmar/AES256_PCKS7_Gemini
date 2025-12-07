import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoServer {

    // Port to expose
    private static final int PORT = 8080;
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding"; // Java's PKCS5 is compatible with PKCS7

    public static void main(String[] args) throws IOException {
        // Create a lightweight HTTP server
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // Contexts (Endpoints)
        server.createContext("/encrypt", new EncryptHandler());
        server.createContext("/decrypt", new DecryptHandler());
        
        server.setExecutor(null); // default executor
        System.out.println("Crypto Service running on port " + PORT);
        server.start();
    }

    // --- ENCRYPTION HANDLER ---
    static class EncryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"POST".equalsIgnoreCase(t.getRequestMethod())) {
                sendResponse(t, 405, "Method Not Allowed. Use POST.");
                return;
            }

            try {
                Map<String, String> params = parseParams(t);
                String text = params.get("text");
                String key = params.get("key");

                if (text == null || key == null) {
                    sendResponse(t, 400, "Missing parameters: 'text' and 'key' are required.");
                    return;
                }

                // 1. Hash key to ensure 256-bit (32 bytes) length
                byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
                SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

                // 2. Generate random IV (16 bytes)
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                // 3. Encrypt
                Cipher cipher = Cipher.getInstance(ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                byte[] encryptedText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

                // 4. Combine IV + EncryptedText (IV is needed for decryption)
                byte[] combined = new byte[iv.length + encryptedText.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encryptedText, 0, combined, iv.length, encryptedText.length);

                // 5. Base64 Encode output
                String result = Base64.getEncoder().encodeToString(combined);
                sendResponse(t, 200, result);

            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(t, 500, "Encryption Error: " + e.getMessage());
            }
        }
    }

    // --- DECRYPTION HANDLER ---
    static class DecryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"POST".equalsIgnoreCase(t.getRequestMethod())) {
                sendResponse(t, 405, "Method Not Allowed. Use POST.");
                return;
            }

            try {
                Map<String, String> params = parseParams(t);
                String encryptedTextBase64 = params.get("text");
                String key = params.get("key");

                if (encryptedTextBase64 == null || key == null) {
                    sendResponse(t, 400, "Missing parameters: 'text' and 'key' are required.");
                    return;
                }

                // 1. Hash key to ensure 256-bit
                byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
                SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

                // 2. Decode Base64
                byte[] combined = Base64.getDecoder().decode(encryptedTextBase64);

                // 3. Extract IV (first 16 bytes)
                byte[] iv = new byte[16];
                System.arraycopy(combined, 0, iv, 0, iv.length);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                // 4. Extract Cipher Text
                int cipherTextLength = combined.length - 16;
                byte[] cipherText = new byte[cipherTextLength];
                System.arraycopy(combined, 16, cipherText, 0, cipherTextLength);

                // 5. Decrypt
                Cipher cipher = Cipher.getInstance(ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
                byte[] decryptedBytes = cipher.doFinal(cipherText);

                sendResponse(t, 200, new String(decryptedBytes, StandardCharsets.UTF_8));

            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(t, 500, "Decryption Error (Check Key or Padding): " + e.getMessage());
            }
        }
    }

    // --- UTILITIES ---
    private static void sendResponse(HttpExchange t, int statusCode, String response) throws IOException {
        t.sendResponseHeaders(statusCode, response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static Map<String, String> parseParams(HttpExchange t) throws IOException {
        Map<String, String> result = new HashMap<>();
        String query = null;
        
        // Handle URL parameters or Body
        if (t.getRequestBody().available() > 0) {
            query = new String(t.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        } else {
            query = t.getRequestURI().getQuery();
        }

        if (query != null) {
            for (String param : query.split("&")) {
                String[] entry = param.split("=");
                if (entry.length > 1) {
                    result.put(entry[0], URLDecoder.decode(entry[1], StandardCharsets.UTF_8));
                }
            }
        }
        return result;
    }
}
