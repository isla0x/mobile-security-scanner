#!/usr/bin/env python3
"""
Mobile App Static Security Scanner (Prototype)
-------------------------------------------------
디컴파일된 앱 소스 폴더(AndroidManifest.xml + Java/Smali 소스)를 입력받아
OWASP MASVS 기준의 대표적인 취약점 패턴을 스캔하고 JSON 리포트를 생성한다.

실제 파이프라인에서는 이 스크립트 앞단에 apktool/jadx로 APK를 디컴파일하는
단계가 들어가고, 이 스크립트는 그 결과물(폴더)을 입력으로 받는다.
"""

import os
import re
import sys
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


# 점수 계산용 가중치 (심각도별 감점)
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    location: str
    masvs_ref: str = ""


@dataclass
class ScanReport:
    findings: list = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def score(self) -> int:
        score = 100
        for f in self.findings:
            score -= SEVERITY_WEIGHT[f.severity]
        return max(score, 0)

    def summary(self):
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self):
        return {
            "score": self.score(),
            "summary": self.summary(),
            "findings": [
                {**asdict(f), "severity": f.severity.value} for f in self.findings
            ],
        }


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def tag(name):
    return f"{{{ANDROID_NS}}}{name}"


# ---------------------------------------------------------------------------
# 1. Manifest 분석
# ---------------------------------------------------------------------------
def scan_manifest(manifest_path: str, report: ScanReport):
    if not os.path.exists(manifest_path):
        return

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    app = root.find("application")

    if app is None:
        return

    if app.get(tag("debuggable")) == "true":
        report.add(Finding(
            id="MANIFEST-DEBUGGABLE",
            title="디버그 모드가 활성화되어 있음 (android:debuggable=true)",
            severity=Severity.HIGH,
            category="매니페스트",
            description="배포용 빌드에서 debuggable 플래그가 켜져 있으면 "
                        "공격자가 디버거를 붙여 런타임 조작이 가능합니다.",
            location="AndroidManifest.xml <application>",
            masvs_ref="MASVS-RESILIENCE",
        ))

    if app.get(tag("allowBackup")) == "true" or app.get(tag("allowBackup")) is None:
        report.add(Finding(
            id="MANIFEST-ALLOWBACKUP",
            title="allowBackup이 허용되어 있음",
            severity=Severity.MEDIUM,
            category="매니페스트",
            description="adb backup 등을 통해 루팅되지 않은 기기에서도 "
                        "앱 데이터가 추출될 수 있습니다.",
            location="AndroidManifest.xml <application>",
            masvs_ref="MASVS-STORAGE-1",
        ))

    if app.get(tag("usesCleartextTraffic")) == "true":
        report.add(Finding(
            id="MANIFEST-CLEARTEXT",
            title="평문 HTTP 트래픽이 허용되어 있음",
            severity=Severity.HIGH,
            category="네트워크",
            description="usesCleartextTraffic=true로 인해 암호화되지 않은 "
                        "통신이 가능해 중간자 공격(MITM)에 노출될 수 있습니다.",
            location="AndroidManifest.xml <application>",
            masvs_ref="MASVS-NETWORK-1",
        ))

    # exported 컴포넌트 (permission 없이 노출된 것들)
    exportable_tags = ["activity", "service", "receiver", "provider"]
    for comp_tag in exportable_tags:
        for comp in app.findall(comp_tag):
            exported = comp.get(tag("exported"))
            has_permission = comp.get(tag("permission")) is not None
            name = comp.get(tag("name"), "unknown")

            if exported == "true" and not has_permission:
                sev = Severity.CRITICAL if comp_tag == "provider" else Severity.MEDIUM
                report.add(Finding(
                    id=f"MANIFEST-EXPORTED-{comp_tag.upper()}",
                    title=f"권한 검증 없이 노출된 {comp_tag}: {name}",
                    severity=sev,
                    category="매니페스트",
                    description=f"{comp_tag}가 exported=true이고 permission이 "
                                f"지정되어 있지 않아, 다른 앱에서 자유롭게 "
                                f"호출/접근할 수 있습니다.",
                    location=f"AndroidManifest.xml <{comp_tag} android:name=\"{name}\">",
                    masvs_ref="MASVS-PLATFORM-1",
                ))


# ---------------------------------------------------------------------------
# 2. 하드코딩 시크릿 스캔
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{20,}", Severity.CRITICAL),
    ("Generic API Key 변수", r"(?i)(api[_-]?key|apikey)\s*=\s*\"[0-9a-zA-Z\-_]{16,}\"", Severity.HIGH),
    ("하드코딩된 비밀번호", r"(?i)(password|passwd|pwd)\s*=\s*\"[^\"]{4,}\"", Severity.HIGH),
    ("JWT/시크릿 키", r"(?i)(secret|jwt[_-]?secret)\s*=\s*\"[^\"]{8,}\"", Severity.HIGH),
]

CRYPTO_PATTERNS = [
    ("취약한 해시 알고리즘: MD5", r"MessageDigest\.getInstance\(\s*\"MD5\"\s*\)", Severity.MEDIUM),
    ("취약한 해시 알고리즘: SHA-1", r"MessageDigest\.getInstance\(\s*\"SHA-1\"\s*\)", Severity.LOW),
    ("취약한 암호화: DES", r"Cipher\.getInstance\(\s*\"DES[/\"]", Severity.HIGH),
    ("취약한 블록 모드: ECB", r"Cipher\.getInstance\(\s*\"[^\"]*\/ECB\/", Severity.HIGH),
]

LOG_PATTERNS = [
    ("민감정보 로그 출력 의심", r"(?:System\.out\.println|Log\.[dviwe])\([^)]*(?:key|password|token|secret)", Severity.MEDIUM),
]

NETWORK_PATTERNS = [
    ("모든 인증서를 신뢰하는 TrustManager", r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}", Severity.CRITICAL),
    ("TrustManager 배열이 비어있음 (검증 무력화)", r"X509TrustManager\s*\[\]\s*\{\s*new\s+X509TrustManager", Severity.CRITICAL),
    ("모든 호스트명을 허용하는 HostnameVerifier", r"ALLOW_ALL_HOSTNAME_VERIFIER", Severity.CRITICAL),
    ("HostnameVerifier가 항상 true 반환", r"HostnameVerifier\s*\(\)\s*\{.*?return\s+true", Severity.CRITICAL),
    ("SSLContext가 커스텀 TrustManager로 초기화됨", r"SSLContext\.getInstance\(\s*\"(SSL|TLS)\"\s*\)", Severity.LOW),
]

WEBVIEW_PATTERNS = [
    ("WebView JavaScript 활성화", r"setJavaScriptEnabled\(\s*true\s*\)", Severity.LOW),
    ("WebView에 JavascriptInterface 노출", r"addJavascriptInterface\(", Severity.HIGH),
    ("WebView 파일 접근 허용", r"setAllowFileAccess\(\s*true\s*\)", Severity.MEDIUM),
    ("혼합 콘텐츠(HTTP/HTTPS) 허용", r"setMixedContentMode\(\s*WebSettings\.MIXED_CONTENT_ALWAYS_ALLOW\s*\)", Severity.MEDIUM),
    ("SSL 오류 무시 (onReceivedSslError)", r"onReceivedSslError\([^)]*\)\s*\{[^}]*\.proceed\(\)", Severity.CRITICAL),
]

STORAGE_PATTERNS = [
    ("외부 저장소에 데이터 직접 쓰기", r"getExternalStorageDirectory\(\)", Severity.MEDIUM),
    ("SharedPreferences에 평문 저장 의심", r"(?i)\.putString\(\s*\"[^\"]*(?:password|token|secret|auth)[^\"]*\"", Severity.HIGH),
    ("World-readable/writable 파일 모드", r"MODE_WORLD_(READABLE|WRITABLE)", Severity.CRITICAL),
    ("SQLite 평문 저장 (암호화 미적용)", r"SQLiteDatabase\.openOrCreateDatabase\(", Severity.INFO),
]

RANDOM_PATTERNS = [
    ("암호화 목적에 부적합한 난수 생성기", r"new\s+Random\(\)", Severity.MEDIUM),
    ("고정된 Seed를 사용하는 난수 생성", r"new\s+Random\(\s*\d+\s*\)", Severity.HIGH),
    ("고정된 IV(초기화 벡터) 사용 의심", r"IvParameterSpec\(\s*\"[^\"]+\"\.getBytes", Severity.HIGH),
]


SUPPRESS_MARKER = "scanner:ignore"


def strip_code_comments(content: str) -> str:
    """
    Java/Kotlin 스타일 주석(// 한 줄 주석, /* 여러 줄 주석*/)을 공백으로 치환한다.
    문자열 리터럴 안의 "//"까지 완벽하게 구분하지는 못하는 단순 구현이지만,
    실제 주석 처리된 취약 코드로 인한 오탐은 거의 다 걸러진다.
    개행 문자는 그대로 유지해서 줄 번호가 틀어지지 않게 한다.
    """
    def replace_block_comment(m):
        # 내용은 지우되 개행은 살려서 라인 번호를 보존
        return "\n" * m.group(0).count("\n")

    # 여러 줄 주석 /* ... */ 제거
    content = re.sub(r"/\*.*?\*/", replace_block_comment, content, flags=re.DOTALL)
    # 한 줄 주석 // ... 제거 (같은 줄 끝까지만, 개행은 유지)
    content = re.sub(r"//[^\n]*", "", content)
    return content


def get_suppressed_lines(raw_content: str) -> set:
    """'scanner:ignore' 마커가 있는 라인 번호를 수집 (해당 라인은 결과에서 제외)."""
    suppressed = set()
    for lineno, line in enumerate(raw_content.splitlines(), start=1):
        if SUPPRESS_MARKER in line:
            suppressed.add(lineno)
    return suppressed


CATEGORY_MASVS = {
    "암호화": "MASVS-CRYPTO-1",
    "네트워크": "MASVS-NETWORK-1",
    "WebView": "MASVS-PLATFORM-2",
    "저장소": "MASVS-STORAGE-1",
    "난수/IV": "MASVS-CRYPTO-1",
    "로깅": "MASVS-STORAGE-2",
    "시크릿 노출": "MASVS-STORAGE-1",
}


def scan_source_files(src_dir: str, report: ScanReport):
    if not os.path.isdir(src_dir):
        return

    all_patterns = [(n, p, s, "시크릿 노출") for n, p, s in SECRET_PATTERNS] + \
                   [(n, p, s, "암호화") for n, p, s in CRYPTO_PATTERNS] + \
                   [(n, p, s, "로깅") for n, p, s in LOG_PATTERNS] + \
                   [(n, p, s, "네트워크") for n, p, s in NETWORK_PATTERNS] + \
                   [(n, p, s, "WebView") for n, p, s in WEBVIEW_PATTERNS] + \
                   [(n, p, s, "저장소") for n, p, s in STORAGE_PATTERNS] + \
                   [(n, p, s, "난수/IV") for n, p, s in RANDOM_PATTERNS]

    for dirpath, _, filenames in os.walk(src_dir):
        for fname in filenames:
            if not fname.endswith((".java", ".kt", ".smali", ".xml")):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    raw_content = f.read()
            except Exception:
                continue

            # 주석 제거된 버전으로 스캔 (오탐 감소), 억제 마커는 원본에서 수집
            is_code_file = fname.endswith((".java", ".kt"))
            content = strip_code_comments(raw_content) if is_code_file else raw_content
            suppressed_lines = get_suppressed_lines(raw_content)

            # 파일 전체를 대상으로 검사 (멀티라인 패턴도 잡기 위해 DOTALL 사용),
            # 매치 위치로부터 실제 라인 번호를 역산한다.
            seen = set()  # (rule_name, lineno) 중복 방지
            for name, pattern, severity, category in all_patterns:
                for m in re.finditer(pattern, content, re.DOTALL):
                    lineno = content.count("\n", 0, m.start()) + 1
                    if lineno in suppressed_lines:
                        continue
                    key = (name, lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    report.add(Finding(
                        id=f"SRC-{re.sub(r'[^A-Z0-9]', '', name.upper())}",
                        title=name,
                        severity=severity,
                        category=category,
                        description=f"패턴 '{name}'이(가) 탐지되었습니다. "
                                    f"소스 코드에서 직접 확인이 필요합니다.",
                        location=f"{os.path.relpath(fpath, src_dir)}:{lineno}",
                        masvs_ref=CATEGORY_MASVS.get(category, "MASVS-CODE-1"),
                    ))


# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------
def run_scan(app_dir: str) -> ScanReport:
    report = ScanReport()
    scan_manifest(os.path.join(app_dir, "AndroidManifest.xml"), report)
    scan_source_files(os.path.join(app_dir, "src"), report)
    return report


def print_human_report(report: ScanReport):
    data = report.to_dict()
    print("=" * 60)
    print(f"  보안 점수: {data['score']} / 100")
    print("=" * 60)
    print("  심각도별 이슈 개수:")
    for sev, count in data["summary"].items():
        if count > 0:
            print(f"    - {sev}: {count}건")
    print("-" * 60)
    for f in sorted(report.findings, key=lambda x: list(Severity).index(x.severity)):
        print(f"[{f.severity.value:8}] {f.title}")
        print(f"           위치: {f.location}")
        print(f"           설명: {f.description}")
        print()


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "./fake_app"
    report = run_scan(target_dir)
    print_human_report(report)

    with open("scan_report.json", "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"\nJSON 리포트 저장됨: scan_report.json")
