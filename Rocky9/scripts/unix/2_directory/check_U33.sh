#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-33"
CATEGORY="파일 및 디렉토리 관리"
TITLE="숨겨진 파일 및 디렉토리 검색 및 제거"
IMPORTANCE="하"
CHECK_DATE=$(date "+%Y-%m-%d %H:%M:%S")

EVIDENCE=""
STATUS="PASS"
TARGET_FILE="/"

# 2. 진단 로직
# 숨겨진 파일 검색 (시스템 주요 디렉토리 기준)
HIDDEN_FILES=$(find / -type f -name ".*" 2>/dev/null | head -n 50)
HIDDEN_DIRS=$(find / -type d -name ".*" 2>/dev/null | head -n 50)

if [[ -n "$HIDDEN_FILES" || -n "$HIDDEN_DIRS" ]]; then
    STATUS="FAIL"
    EVIDENCE="Hidden files:\n$HIDDEN_FILES\n\nHidden directories:\n$HIDDEN_DIRS"
else
    EVIDENCE="No hidden files or directories detected."
fi

# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$(echo -e "$EVIDENCE" | sed 's/"/\\"/g')",
  "target_file": "$TARGET_FILE",
  "file_hash": "N/A",
  "check_date": "$CHECK_DATE"
}
EOF