#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev에 존재하지 않는 device 파일 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-26"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/dev/*"
CHECK_COMMAND='find /dev -type f 2>/dev/null'

DETAIL_CONTENT=""
REASON_LINE=""

# /dev 디렉터리 내 일반 파일 탐색
INVALID_FILES=$(find /dev -type f 2>/dev/null)

# 결과 유무에 따른 PASS/FAIL 결정
if [ -n "$INVALID_FILES" ]; then
  STATUS="FAIL"
  REASON_LINE="/dev 디렉터리에 일반 파일이 존재하여 정상적인 디바이스 노드가 아닌 파일이 포함될 가능성이 있고, 악성 파일이 위장되어 동작하거나 보안 정책을 우회할 위험이 있으므로 취약합니다. 해당 파일들을 확인 후 불필요한 파일은 제거해야 합니다."
  DETAIL_CONTENT="$INVALID_FILES"
else
  STATUS="PASS"
  REASON_LINE="/dev 디렉터리에 일반 파일이 존재하지 않아 비정상적인 디바이스 위장 파일로 인한 보안 위협이 없으므로 이 항목에 대한 보안 위협이 없습니다."
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