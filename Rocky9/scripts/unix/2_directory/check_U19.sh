#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-19"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/hosts 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/hosts"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

STATUS="FAIL"
EVIDENCE=""

# 2. 진단 로직
if [ -f "$TARGET_FILE" ]; then
    FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$FILE_OWNER" = "root" ] && [ "$FILE_PERM" -le 644 ]; then
        STATUS="PASS"
        EVIDENCE="소유자: $FILE_OWNER, 권한: $FILE_PERM"
    else
        STATUS="FAIL"
        EVIDENCE="소유자: $FILE_OWNER, 권한: $FILE_PERM (기준: root / 644 이하)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="/etc/hosts 파일이 존재하지 않음"
fi

# 3. 결과 출력 (JSON)
cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "target_file": "$TARGET_FILE",
  "check_date": "$CHECK_DATE"
}
EOF