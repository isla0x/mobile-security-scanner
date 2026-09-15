package com.example.app;

import android.webkit.WebView;
import android.webkit.WebSettings;
import android.content.SharedPreferences;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;

public class NetworkAndWebViewSetup {

    public void setupInsecureWebView(WebView webView) {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        webView.addJavascriptInterface(new Object(), "AndroidBridge");
    }

    public void savePrefs(SharedPreferences prefs, String token) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("auth_token", token);
        editor.apply();
    }

    // 모든 인증서를 신뢰하는 TrustManager (검증 무력화)
    X509TrustManager trustAllCerts = new X509TrustManager() {
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    };

    HostnameVerifier trustAllHostnames = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    public byte[] weakRandomToken() {
        Random r = new Random(1234);
        byte[] token = new byte[16];
        r.nextBytes(token);
        return token;
    }

    public IvParameterSpec fixedIv() {
        return new IvParameterSpec("1234567890123456".getBytes());
    }
}
