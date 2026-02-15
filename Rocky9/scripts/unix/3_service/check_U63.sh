#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Criteria_Good :  /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우
# @Criteria_Bad : /etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-63 sudo 명령어 접근 관리

# 기본 변수
ID="U-63"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/sudoers"
CHECK_COMMAND='stat -c "%U %G %a %n" /etc/sudoers 2>/dev/null || echo "sudoers_not_found_or_stat_failed"'

REASON_LINE=""
DETAIL_CONTENT=""
VULNERABLE=0

if [ ! -f "$TARGET_FILE" ]; then
  STATUS="PASS"
  REASON_LINE="/etc/sudoers 파일이 존재하지 않아 sudo 설정 파일을 점검할 수 없습니다. (sudo 미설치 또는 별도 정책 적용 환경일 수 있어 확인이 필요하며, 해당 파일 기준으로는 보안 위협이 없습니다.)"
  DETAIL_CONTENT="확인 결과: /etc/sudoers 없음"
else
  OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
  GROUP="$(stat -c '%G' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
  PERM_STR="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || echo "unknown")"

  DETAIL_CONTENT="현재 설정: owner=${OWNER}, group=${GROUP}, perm=${PERM_STR}"

  OWNER_OK=0
  PERM_OK=0

  [ "$OWNER" = "root" ] && OWNER_OK=1

  if echo "$PERM_STR" | grep -Eq '^[0-7]{3,4}$'; then
    PERM_DEC=$((8#$PERM_STR))
    BASE_DEC=$((8#640))
    [ "$PERM_DEC" -le "$BASE_DEC" ] && PERM_OK=1
  fi

  if [ "$OWNER_OK" -ne 1 ] || [ "$PERM_OK" -ne 1 ]; then
    VULNERABLE=1
  fi

  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/sudoers 파일이 owner=${OWNER}, perm=${PERM_STR} 로 설정되어 있어(소유자 root가 아니거나 권한이 640을 초과) 취약합니다. 조치: chown root /etc/sudoers && chmod 640 /etc/sudoers"
  else
    STATUS="PASS"
    REASON_LINE="/etc/sudoers 파일이 소유자 root이고 권한이 640 이하로 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g; :a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF