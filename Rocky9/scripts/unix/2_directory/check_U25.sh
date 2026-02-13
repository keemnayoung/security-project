#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : 불필요한 world writable 파일 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-25"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/"
CHECK_COMMAND='find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null'

TMP_RESULT_FILE="/tmp/U25_world_writable_files.txt"
DETAIL_CONTENT=""
REASON_LINE=""

# world writable 파일 탐색 (결과는 임시 파일에 저장)
find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_RESULT_FILE"

FILE_COUNT=$(wc -l < "$TMP_RESULT_FILE" 2>/dev/null | tr -d ' ')

# 결과 유무에 따른 PASS/FAIL 결정
if [ "$FILE_COUNT" -eq 0 ]; then
    STATUS="PASS"
    REASON_LINE="world writable 권한이 설정된 파일이 존재하지 않아 비인가 사용자가 파일을 임의로 수정할 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="none"
else
    STATUS="FAIL"
    REASON_LINE="world writable 권한이 설정된 파일이 존재하여 비인가 사용자가 파일을 임의로 수정하거나 악성 코드 삽입을 할 위험이 있으므로 취약합니다. 불필요한 world writable 권한을 제거하거나 해당 파일을 제거해야 합니다."
    DETAIL_CONTENT="$(cat "$TMP_RESULT_FILE")"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF

# 임시 파일 정리
rm -f "$TMP_RESULT_FILE"