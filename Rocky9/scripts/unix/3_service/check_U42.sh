#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Criteria_Good : 불필요한 RPC 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 RPC 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-42 불필요한 RPC 서비스 비활성화

# 기본 변수
ID="U-42"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="N/A"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -Ev "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*rpc" ) ; ( [ -d /etc/xinetd.d ] && grep -RniE "^[[:space:]]*service[[:space:]]+.*rpc|disable[[:space:]]*=[[:space:]]*no" /etc/xinetd.d 2>/dev/null | head -n 50 ) ; systemctl list-units --type=service 2>/dev/null | grep -i rpc || echo "no_rpc_related_services"'

DETAIL_CONTENT=""
REASON_LINE=""

VULN_DETAILS=()

# 1) inetd 기반 RPC 서비스 (주석 제외 후 rpc로 시작하는 서비스 라인)
if [ -f "/etc/inetd.conf" ]; then
  RPC_INETD=$(grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*rpc" | head -n 50)
  if [ -n "$RPC_INETD" ]; then
    VULN_DETAILS+=("[inetd:/etc/inetd.conf] rpc 항목 활성화 의심:\n${RPC_INETD}")
  fi
fi

# 2) xinetd 기반 RPC 관련 서비스 (파일명에 rpc 포함 또는 service 라인에 rpc 포함 + disable=no)
if [ -d "/etc/xinetd.d" ]; then
  while IFS= read -r conf; do
    [ -f "$conf" ] || continue

    # rpc 관련 파일/서비스인지 확인(주석 제외)
    IS_RPC=0
    echo "$conf" | grep -qi "rpc" && IS_RPC=1
    if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+.*rpc"; then
      IS_RPC=1
    fi

    if [ "$IS_RPC" -eq 1 ]; then
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        VULN_DETAILS+=("[xinetd:${conf}] disable=no 로 활성화됨")
      fi
    fi
  done < <(find /etc/xinetd.d -maxdepth 1 -type f 2>/dev/null | sort)
fi

# 3) systemd 기반 RPC 관련 서비스 활성화 여부
RPC_SYSTEMD=$(systemctl list-units --type=service 2>/dev/null | grep -i "rpc" | awk '{print $1}' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')
if [ -n "$RPC_SYSTEMD" ]; then
  VULN_DETAILS+=("[systemd] rpc 관련 서비스 감지: ${RPC_SYSTEMD}")
fi

# 종합 판단
if [ "${#VULN_DETAILS[@]}" -gt 0 ]; then
  STATUS="FAIL"
  REASON_LINE="불필요한 RPC 관련 서비스가 활성화되어 있어 원격 호출 기반 공격면이 증가하므로 취약합니다. (예: rpcbind 등) 사용 목적(NFS 등)과 의존성을 확인한 뒤 불필요하면 중지/비활성화가 필요합니다."
  DETAIL_CONTENT=$(printf "%s\n\n" "${VULN_DETAILS[@]}")
else
  STATUS="PASS"
  REASON_LINE="inetd/xinetd/systemd에서 RPC 관련 서비스 활성화 징후가 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="no_rpc_service_active"
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