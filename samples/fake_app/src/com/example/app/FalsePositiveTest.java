package com.example.app;

import java.security.MessageDigest;

/**
 * 예전에 쓰던 취약한 구현 (지금은 안 씀):
 * MessageDigest md = MessageDigest.getInstance("MD5");
 * String API_KEY = "REDACTED_SAMPLE_KEY_OLD_NOT_REAL_0000";
 */
public class FalsePositiveTest {

    // String password = "old_hardcoded_password_1234"; <- 주석 처리된 예전 코드, 걸리면 안 됨

    public void intentionalTestKeyForCiPipeline() {
        // 테스트/CI 환경에서만 쓰는 더미 키. 오탐이라 억제 처리함
        String testApiKey = "REDACTED_SAMPLE_KEY_FOR_CI_0000000000"; // scanner:ignore

        // 아래는 억제 마커가 없어서 정상적으로 잡혀야 함 (대조군)
        String realLookingSecret = "REDACTED_SAMPLE_KEY_REAL_LOOKING_0000";
    }
}
