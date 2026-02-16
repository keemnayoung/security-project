#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-43 NIS, NIS+ 점검

# 1. 항목 정보 정의
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
STATUS="PASS"
ACTION_LOG=""
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검/조치 대상 유닛(가이드 기준)
NIS_UNITS=("ypserv.service" "ypbind.service" "ypxfrd.service" "rpc.yppasswdd.service" "rpc.ypupdated.service")

CHECK_COMMAND="systemctl list-units --type=service | grep -E 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated'; systemctl is-active/is-enabled <unit>"

# systemctl 사용 가능 여부 확인
if ! command -v systemctl >/dev/null 2>&1; then
  STATUS="ERROR"
  ACTION_LOG="systemctl 명령을 사용할 수 없어 NIS 관련 서비스 조치를 수행하지 못했습니다."
else
  # (참고) 현재 active인 유닛 목록(로그용)
  NIS_SERVICES_ACTIVE="$(systemctl list-units --type=service 2>/dev/null | awk '{print $1}' | grep -E 'ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated' | tr '\n' ' ')"

  # [Step 2~3] stop/disable 수행 (active 뿐 아니라 enabled도 함께 처리)
  for unit in "${NIS_UNITS[@]}"; do
    # enabled 여부(부팅 자동 시작)
    en_state="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"
    # active 여부(현재 실행)
    ac_state="$(systemctl is-active "$unit" 2>/dev/null | tr -d '\r')"

    if [ "$ac_state" = "active" ]; then
      if systemctl stop "$unit" >/dev/null 2>&1; then
        ACTION_LOG="${ACTION_LOG}${unit} 중지; "
      else
        ACTION_LOG="${ACTION_LOG}${unit} 중지 실패; "
      fi
    fi

    if [ "$en_state" = "enabled" ]; then
      if systemctl disable "$unit" >/dev/null 2>&1; then
        ACTION_LOG="${ACTION_LOG}${unit} 비활성화; "
      else
        ACTION_LOG="${ACTION_LOG}${unit} 비활성화 실패; "
      fi
    fi
  done

  # [최종 검증] 조치 후 active/enabled 잔존 여부로 PASS/FAIL 결정
  AFTER_ACTIVE=""
  AFTER_ENABLED=""

  for unit in "${NIS_UNITS[@]}"; do
    ac_after="$(systemctl is-active "$unit" 2>/dev/null | tr -d '\r')"
    en_after="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"

    if [ "$ac_after" = "active" ]; then
      AFTER_ACTIVE+="${unit} "
    fi
    if [ "$en_after" = "enabled" ]; then
      AFTER_ENABLED+="${unit} "
    fi
  done

  if [ -n "$AFTER_ACTIVE" ] || [ -n "$AFTER_ENABLED" ]; then
    STATUS="FAIL"
  else
    STATUS="PASS"
  fi
fi

# raw_evidence 구성: REASON_LINE + DETAIL_CONTENT (2줄 구조)
REASON_LINE=""
DETAIL_CONTENT=""

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="NIS 관련 서비스가 중지/비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(점검 명령) ${CHECK_COMMAND}\n(조치 로그) ${ACTION_LOG:-'조치 대상 없음(이미 양호)'}\n(조치 후) active: 없음\n(조치 후) enabled: 없음"
elif [ "$STATUS" = "FAIL" ]; then
  REASON_LINE="NIS 관련 서비스가 조치 이후에도 active 또는 enabled로 남아 있어 취약합니다."
  DETAIL_CONTENT="(점검 명령) ${CHECK_COMMAND}\n(조치 로그) ${ACTION_LOG:-'조치 시도 없음'}\n(조치 후) active: ${AFTER_ACTIVE:-없음}\n(조치 후) enabled: ${AFTER_ENABLED:-없음}\n(간단 조치) 남아있는 서비스에 대해 'systemctl stop <unit> && systemctl disable <unit>' 수행 후 재점검"
else
  # ERROR
  REASON_LINE="$ACTION_LOG"
  DETAIL_CONTENT="(점검 명령) ${CHECK_COMMAND}\n(조치 후) 상태 확인 불가"
fi

json_escape() {
  # 백슬래시/따옴표/줄바꿈 escape
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(json_escape "$CHECK_COMMAND")",
  "detail":"$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(json_escape "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat << EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF