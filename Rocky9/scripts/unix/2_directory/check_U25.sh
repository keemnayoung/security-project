#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : 불필요한 world writable 파일 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-25"
CATEGORY="파일 및 디렉토리 관리"
TITLE="world writable 파일 점검"
IMPORTANCE="상"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 2. 진단 로직
TARGET_FILE="/"
TMP_RESULT_FILE="/tmp/u25_world_writable_files.txt"

# world writable 파일 탐색
find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_RESULT_FILE"

FILE_COUNT=$(wc -l < "$TMP_RESULT_FILE")

if [ "$FILE_COUNT" -eq 0 ]; then
    STATUS="PASS"
    EVIDENCE="world writable 파일이 존재하지 않음"
else
    STATUS="FAIL"
    EVIDENCE="world writable 파일이 존재함 (설정 인지 여부 확인 필요)"
fi

# 3. 무결성 정보
if command -v sha256sum >/dev/null 2>&1; then
    FILE_HASH=$(sha256sum "$TMP_RESULT_FILE" | awk '{print $1}')
else
    FILE_HASH="N/A"
fi

# 4. 마스터 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "target_file": "$TARGET_FILE",
  "file_hash": "$FILE_HASH",
  "check_date": "$CHECK_DATE"
}
EOF

# 5. 임시 파일 정리
rm -f "$TMP_RESULT_FILE"