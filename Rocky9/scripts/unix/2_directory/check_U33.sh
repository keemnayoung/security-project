#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-33"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/"
CHECK_COMMAND='find / -type f -name ".*" 2>/dev/null | head -n 50; find / -type d -name ".*" 2>/dev/null | head -n 50'

DETAIL_CONTENT=""
REASON_LINE=""

# 숨겨진 파일/디렉터리 검색 (상위 50개)
HIDDEN_FILES_RAW=$(find / -type f -name ".*" 2>/dev/null | head -n 50)
HIDDEN_DIRS_RAW=$(find / -type d -name ".*" 2>/dev/null | head -n 50)

# 결과 유무에 따른 PASS/FAIL 결정
if [[ -n "$HIDDEN_FILES_RAW" || -n "$HIDDEN_DIRS_RAW" ]]; then
    STATUS="FAIL"
    REASON_LINE="서버에서 숨겨진 파일 또는 숨겨진 디렉터리가 발견되어 비인가 은닉 파일/설정이 존재할 가능성이 있으므로 취약합니다. 각 항목의 용도를 확인하고 불법적이거나 의심스러운 파일/디렉터리는 제거해야 합니다."

    DETAIL_CONTENT="Hidden_files:"$'\n'
    if [ -n "$HIDDEN_FILES_RAW" ]; then
        DETAIL_CONTENT+="$HIDDEN_FILES_RAW"$'\n'
    else
        DETAIL_CONTENT+="none"$'\n'
    fi

    DETAIL_CONTENT+="Hidden_directories:"$'\n'
    if [ -n "$HIDDEN_DIRS_RAW" ]; then
        DETAIL_CONTENT+="$HIDDEN_DIRS_RAW"
    else
        DETAIL_CONTENT+="none"
    fi
else
    STATUS="PASS"
    REASON_LINE="서버 전체에서 숨겨진 파일이나 숨겨진 디렉터리가 발견되지 않아 비인가 은닉 파일이 존재할 가능성이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="none"
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