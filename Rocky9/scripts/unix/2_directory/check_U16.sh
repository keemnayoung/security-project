#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-16"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/passwd 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
FILE_HASH="N/A"

# 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    EVIDENCE="/etc/passwd 파일이 존재하지 않음"
else
    FILE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    FILE_PERM=$(stat -c "%a" "$TARGET_FILE")

    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 644 ]; then
        STATUS="FAIL"
        EVIDENCE="/etc/passwd 파일 설정 부적절 (owner=$FILE_OWNER, perm=$FILE_PERM)"
    else
        EVIDENCE="/etc/passwd 파일 소유자(root) 및 권한(644 이하) 설정이 적절함"
    fi
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "target_file": "$TARGET_FILE",
  "file_hash": "$FILE_HASH",
  "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
