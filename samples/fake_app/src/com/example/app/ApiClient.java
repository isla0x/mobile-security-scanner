package com.example.app;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ApiClient {

    // 하드코딩된 시크릿들
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String API_KEY = "REDACTED_SAMPLE_KEY_NOT_A_REAL_SECRET_0000";
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String JWT_SECRET = "my-super-secret-jwt-key-do-not-share";

    public static String hashPassword(String password) throws Exception {
        // 취약한 해시 알고리즘 사용
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return bytesToHex(digest);
    }

    public static byte[] encryptData(byte[] data, byte[] key) throws Exception {
        // 취약한 암호화: DES + ECB 모드
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    public static void logRequest(String url) {
        // 민감정보 로그 노출
        System.out.println("Requesting: " + url + " with key=" + API_KEY);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
