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

TARGET_FILE="/dev (exclude: /dev/mqueue, /dev/shm)"
CHECK_COMMAND='find /dev -type f -exec ls -l {} \; (exclude: /dev/mqueue, /dev/shm)'

DETAIL_CONTENT=""
REASON_LINE=""

# /dev 디렉터리 내 일반 파일 탐색 (가이드 예외: /dev/mqueue, /dev/shm)
INVALID_FILES=$(find /dev \
  \( -path /dev/mqueue -o -path /dev/mqueue/\* -o -path /dev/shm -o -path /dev/shm/\* \) -prune -o \
  -type f -print 2>/dev/null)

# 결과 유무에 따른 PASS/FAIL 결정
if [ -n "$INVALID_FILES" ]; then
  STATUS="FAIL"
  REASON_LINE="/dev 디렉터리에 정상적인 디바이스 노드가 아닌 일반 파일이 존재합니다. 이는 악성 파일이 디바이스 파일로 위장하거나 보안 정책을 우회할 위험이 있어 취약합니다. (가이드 예외 경로: /dev/mqueue, /dev/shm 제외)"

  # 여러 경로는 줄바꿈이 아닌 쉼표로 구분(요구사항 반영)
  INVALID_FILES_CSV=$(echo "$INVALID_FILES" | paste -sd ", " -)

  # 가이드 예시 반영: ls -l로 소유자/권한 근거 추가
  LS_INFO=$(echo "$INVALID_FILES" | xargs -r ls -l 2>/dev/null)

  DETAIL_CONTENT="발견 파일(쉼표 구분): $INVALID_FILES_CSV
ls -l 결과:
$LS_INFO"
else
  STATUS="PASS"
  REASON_LINE="/dev 디렉터리에 일반 파일이 존재하지 않습니다. (가이드 예외 경로: /dev/mqueue, /dev/shm 제외)"
  DETAIL_CONTENT="none"
fi

# raw_evidence 구성
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