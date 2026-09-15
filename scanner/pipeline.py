#!/usr/bin/env python3
"""
APK -> 디컴파일 -> 정적 분석 파이프라인
-------------------------------------------------
실제 APK 파일 하나를 받아서:
  1. apktool로 AndroidManifest.xml + 리소스를 디코딩
  2. jadx로 .dex를 Java 소스로 디컴파일
  3. scanner.py가 기대하는 구조(<out>/AndroidManifest.xml, <out>/src/...)로 정리
  4. scanner.py를 그대로 호출해서 리포트 생성

사전 준비물 (둘 다 자바만 있으면 실행 가능한 jar/스크립트):
  - apktool.jar  (https://github.com/iBotPeaches/Apktool)
  - jadx         (https://github.com/skylot/jadx)

사용법:
  python3 pipeline.py app.apk --apktool /path/to/apktool.jar --jadx /path/to/jadx/bin/jadx
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# scanner.py를 같은 프로젝트에서 import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import run_scan, print_human_report  # noqa: E402

import json


def run(cmd, label):
    print(f"[*] {label} ...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] {label} 실패 (exit={result.returncode})")
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
        raise RuntimeError(f"{label} failed")
    print(f"[✓] {label} 완료")


def decompile_apk(apk_path: str, apktool_jar: str, jadx_bin: str, workdir: str) -> str:
    """
    APK를 디컴파일해서 scanner.py가 기대하는 구조의 폴더 경로를 반환한다:
        <workdir>/unified/AndroidManifest.xml
        <workdir>/unified/src/...  (jadx가 뽑은 자바 소스)
    """
    apktool_out = os.path.join(workdir, "apktool_out")
    jadx_out = os.path.join(workdir, "jadx_out")
    unified = os.path.join(workdir, "unified")

    # 1. apktool: 매니페스트 + 리소스
    run(
        ["java", "-jar", apktool_jar, "d", "-f", apk_path, "-o", apktool_out],
        "apktool로 매니페스트/리소스 디코딩",
    )

    # 2. jadx: 자바 소스
    run(
        [jadx_bin, "-d", jadx_out, apk_path],
        "jadx로 자바 소스 디컴파일",
    )

    # 3. scanner.py가 기대하는 구조로 정리
    os.makedirs(unified, exist_ok=True)

    manifest_src = os.path.join(apktool_out, "AndroidManifest.xml")
    manifest_dst = os.path.join(unified, "AndroidManifest.xml")
    if os.path.exists(manifest_src):
        shutil.copy2(manifest_src, manifest_dst)
    else:
        print("[!] AndroidManifest.xml을 찾지 못했습니다 (apktool 출력 확인 필요)")

    jadx_sources = os.path.join(jadx_out, "sources")
    unified_src = os.path.join(unified, "src")
    if os.path.exists(jadx_sources):
        if os.path.exists(unified_src):
            shutil.rmtree(unified_src)
        shutil.copytree(jadx_sources, unified_src)
    else:
        print("[!] jadx sources 폴더를 찾지 못했습니다")

    return unified


def main():
    parser = argparse.ArgumentParser(description="APK 디컴파일 + 정적 분석 파이프라인")
    parser.add_argument("apk", help="분석할 APK 파일 경로")
    parser.add_argument("--apktool", required=True, help="apktool.jar 경로")
    parser.add_argument("--jadx", required=True, help="jadx 실행 파일 경로 (jadx/bin/jadx)")
    parser.add_argument("--keep-workdir", action="store_true",
                         help="중간 디컴파일 결과물을 지우지 않고 보존")
    parser.add_argument("-o", "--output", default="scan_report.json",
                         help="결과 JSON 저장 경로 (기본값: scan_report.json)")
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"[!] APK 파일을 찾을 수 없습니다: {apk_path}")
        sys.exit(1)

    workdir = tempfile.mkdtemp(prefix="apk_pipeline_")
    try:
        unified_dir = decompile_apk(apk_path, args.apktool, args.jadx, workdir)

        print("[*] 정적 분석 스캐너 실행 중 ...")
        report = run_scan(unified_dir)
        print_human_report(report)

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"\n[✓] JSON 리포트 저장됨: {args.output}")

        if args.keep_workdir:
            print(f"[i] 디컴파일 중간 결과물 위치: {workdir}")
    finally:
        if not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
