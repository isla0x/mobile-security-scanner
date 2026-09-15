# Mobile App Security Scanner (Prototype)

APK를 디컴파일한 소스/매니페스트를 넣으면 [OWASP MASVS](https://mas.owasp.org/MASVS/)
기준으로 정적 취약점을 스캔하고, 심각도별 점수와 리포트를 만들어주는 프로토타입입니다.

> ⚠️ 이 프로젝트는 **자기 앱을 진단하기 위한 정적 분석 도구**입니다.
> 루팅 탐지 우회, 안티-치트 무력화 등 다른 앱의 보안 장치를 뚫는 코드는
> 포함하지 않으며, 앞으로도 포함할 계획이 없습니다.

## 구성

```
.
├── scanner/
│   ├── scanner.py          # 정적 분석 엔진 (매니페스트 + 소스 코드 룰 스캔)
│   └── pipeline.py         # 실제 APK -> apktool/jadx 디컴파일 -> scanner.py 자동 연결
├── dashboard/
│   └── dashboard.html      # 스캔 결과(JSON)를 보여주는 웹 대시보드
├── samples/
│   ├── fake_app/           # 테스트용 취약점이 심어진 더미 안드로이드 프로젝트
│   ├── scan_report.json    # scanner.py를 fake_app에 돌린 결과 예시
│   └── real_apk_example/   # 실제 오픈소스 APK를 파이프라인으로 스캔한 결과 예시
└── docs/
    └── PLANNING.md         # 기획 배경, MVP 로드맵, 논의 히스토리
```

## 빠른 시작

### 1. 정적 분석 실행

```bash
cd scanner
python3 scanner.py ../samples/fake_app
```

`AndroidManifest.xml`과 `src/` 아래의 `.java` / `.kt` / `.smali` 파일을 스캔해서
콘솔에 사람이 읽기 좋은 리포트를 출력하고, `scan_report.json`으로도 저장합니다.

### 2. 실제 APK 파일 스캔 (apktool + jadx 파이프라인)

디컴파일까지 자동으로 해주는 파이프라인 스크립트입니다.
[apktool](https://github.com/iBotPeaches/Apktool)과 [jadx](https://github.com/skylot/jadx)만
설치되어 있으면 됩니다 (둘 다 Java만 있으면 실행 가능).

```bash
cd scanner
python3 pipeline.py /path/to/app.apk \
  --apktool /path/to/apktool.jar \
  --jadx /path/to/jadx/bin/jadx
```

내부적으로 apktool로 `AndroidManifest.xml`을 디코딩하고, jadx로 `.dex`를 Java 소스로
디컴파일한 뒤, `scanner.py`가 기대하는 구조로 합쳐서 그대로 스캔합니다.
`samples/real_apk_example/scan_report.json`은 실제 오픈소스 APK
([openstf/adbkit-apkreader](https://github.com/openstf/adbkit-apkreader)의
테스트 픽스처)로 이 파이프라인을 실행한 결과입니다 (점수 29/100, debuggable/allowBackup/
외부 저장소 직접 쓰기 등 8개 이슈 탐지).

### 3. 대시보드로 결과 보기

`dashboard/dashboard.html` 파일을 브라우저로 열면 기본 예시 리포트가 바로 보입니다.
우측 상단의 **"다른 리포트 불러오기"** 버튼으로 직접 만든 `scan_report.json`을
업로드해서 시각화할 수 있습니다. (별도 서버 없이 로컬 파일로 동작)

## 현재 스캔 룰 (7개 카테고리, 24개 룰)

| 카테고리 | 예시 |
|---|---|
| 매니페스트 | debuggable, allowBackup, cleartext traffic, exported 컴포넌트 |
| 시크릿 노출 | AWS 키, Stripe 키, 하드코딩된 비밀번호/JWT 시크릿 |
| 암호화 | MD5/SHA-1, DES, ECB 모드 |
| 네트워크 | TrustManager/HostnameVerifier 무력화, SSL 오류 무시 |
| WebView | JavascriptInterface 노출, 파일 접근 허용, 혼합 콘텐츠 |
| 저장소 | SharedPreferences 평문 저장, world-readable 파일 |
| 난수/IV | 취약한 Random, 고정 IV |

오탐을 줄이기 위해 주석 처리된 코드는 자동으로 스캔에서 제외되고,
`// scanner:ignore` 마커가 붙은 줄은 결과에서 제외됩니다.

`samples/fake_app`의 더미 시크릿 값은 전부 `REDACTED_...` 형태로 되어 있어
실제 키 형식과 겹치지 않습니다 (GitHub Push Protection 등 시크릿 스캐너와
충돌하지 않도록 의도적으로 그렇게 만들었습니다).

## 로드맵

- [x] 정적 분석 룰 엔진 프로토타입
- [x] MASVS 기준 스코어링
- [x] 웹 대시보드 (JSON 시각화)
- [x] 실제 APK → apktool/jadx 디컴파일 파이프라인 연동
- [ ] 동적 분석 (에뮬레이터 + 트래픽 캡처)
- [ ] Android 앱 클라이언트

자세한 기획 배경과 논의 내용은 [`docs/PLANNING.md`](docs/PLANNING.md)를 참고하세요.

## 라이선스

TBD
