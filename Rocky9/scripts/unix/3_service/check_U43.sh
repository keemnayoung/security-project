#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Criteria_Good : NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우
# @Criteria_Bad : NIS 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-43 NIS, NIS+ 점검

# 1. 항목 정보 정의
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 가이드 기준 점검 대상(서비스 유닛)
NIS_UNIT_REGEX='^(ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated)\.service$'
NIS_UNITS=("ypserv.service" "ypbind.service" "ypxfrd.service" "rpc.yppasswdd.service" "rpc.ypupdated.service")

CHECK_COMMAND="systemctl list-units --type=service | grep -E 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated'; systemctl is-active/is-enabled <unit>"

REASON_LINE=""
DETAIL_CONTENT=""

ACTIVE_FOUND=""
ENABLED_FOUND=""
FOUND_ANY=0

# systemctl 사용 가능 여부(대상: Rocky Linux 9/10은 일반적으로 systemd)
if ! command -v systemctl >/dev/null 2>&1; then
  STATUS="ERROR"
  REASON_LINE="systemctl 명령을 사용할 수 없어 NIS 관련 서비스 활성화 여부를 점검하지 못했습니다."
  DETAIL_CONTENT="(점검 불가) systemctl 미존재"
else
  # [1] 현재 실행(활성) 상태 점검: list-units는 주로 active 대상
  ACTIVE_LIST="$(systemctl list-units --type=service 2>/dev/null | awk '{print $1}' | grep -E 'ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated' | tr '\n' ' ')"
  if [ -n "$ACTIVE_LIST" ]; then
    ACTIVE_FOUND="$ACTIVE_LIST"
    FOUND_ANY=1
  fi

  # [2] enabled(부팅 시 자동 시작) 상태 점검: 지금은 꺼져 있어도 enabled면 관리 필요
  for unit in "${NIS_UNITS[@]}"; do
    # 유닛이 존재할 때만 enabled 여부 확인(없으면 "disabled"/"not-found" 등)
    en_state="$(systemctl is-enabled "$unit" 2>/dev/null | tr -d '\r')"
    if [ "$en_state" = "enabled" ]; then
      ENABLED_FOUND+="${unit} "
      FOUND_ANY=1
    fi
  done

  if [ "$FOUND_ANY" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="systemctl에서 NIS 관련 서비스가 활성(active) 또는 부팅 시 자동 시작(enabled)으로 설정되어 있어 취약합니다."
    DETAIL_CONTENT="(점검 명령) ${CHECK_COMMAND}\n(판정 결과) active: ${ACTIVE_FOUND:-없음}\n(판정 결과) enabled: ${ENABLED_FOUND:-없음}\n(간단 조치) 불필요 시 'systemctl stop <서비스> && systemctl disable <서비스>'로 비활성화 후 재점검 (예: systemctl stop ypserv ypbind; systemctl disable ypserv ypbind)."
  else
    STATUS="PASS"
    REASON_LINE="systemctl에서 NIS 관련 서비스가 active 또는 enabled로 설정되어 있지 않아 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="(점검 명령) ${CHECK_COMMAND}\n(판정 결과) active/enabled 모두 없음"
  fi
fi

escape_json_str() {
  # 백슬래시 -> \\ , 줄바꿈 -> \n , 따옴표 -> \"
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF