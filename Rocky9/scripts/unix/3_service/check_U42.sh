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

# 불필요한 RPC 서비스(가이드 기준)
UNNEEDED_RPC_SERVICES=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd"
  "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad"
  "kcms_server" "cachefsd"
)

# 점검 명령(보고서용)
CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null ) || echo "inetd_conf_not_found";
( [ -d /etc/xinetd.d ] && for f in /etc/xinetd.d/*; do [ -f "$f" ] && (echo "### $f"; grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null); done | head -n 300 ) || echo "xinetd_dir_not_found";
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files --type=service 2>/dev/null | head -n 200;
  systemctl list-units --type=service --all 2>/dev/null | head -n 200
)) || echo "systemctl_not_found"
'

DETAIL_CONTENT=""
REASON_LINE=""
VULN_DETAILS=()

# -----------------------------
# 1) inetd 기반 점검: /etc/inetd.conf (주석 제외)
# -----------------------------
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
    # inetd는 보통 첫 컬럼이 서비스명(공백/탭 기준)
    HIT=$(grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*${svc}([[:space:]]|$)" | head -n 20)
    if [ -n "$HIT" ]; then
      VULN_DETAILS+=("[inetd:/etc/inetd.conf] ${svc} 항목이 활성(주석 제외)로 존재합니다:\n${HIT}")
    fi
  done
fi

# -----------------------------
# 2) xinetd 기반 점검: /etc/xinetd.d/*
#    - service <name> 블록이 존재하고, disable = no 인 경우 취약으로 판단(가이드 기준)
# -----------------------------
if [ -d "/etc/xinetd.d" ]; then
  while IFS= read -r conf; do
    [ -f "$conf" ] || continue
    for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
      # 주석 제외 후 service 명칭 매칭
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)"; then
        # disable = no 인 경우
        if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
          LINE=$(grep -nEi "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)|^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" "$conf" 2>/dev/null | head -n 20)
          VULN_DETAILS+=("[xinetd:${conf}] ${svc} 서비스가 disable=no 로 활성화되어 있습니다:\n${LINE}")
        fi
      fi
    done
  done < <(find /etc/xinetd.d -maxdepth 1 -type f 2>/dev/null | sort)
fi

# -----------------------------
# 3) systemd 기반 점검
#    - 목록 서비스명 기반으로 유닛 존재 여부 확인 후 enabled/active면 취약
# -----------------------------
if command -v systemctl >/dev/null 2>&1; then
  for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
    unit="${svc}.service"

    # 유닛 존재 확인(둘 중 하나라도 걸리면 존재로 판단)
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
      # enabled / active 확인
      EN=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
      AC=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")

      if [ "$EN" = "enabled" ] || [ "$AC" = "active" ]; then
        VULN_DETAILS+=("[systemd] ${unit} 상태: enabled=${EN}, active=${AC} (불필요 RPC 서비스 활성)")
      fi
    fi
  done
fi

# -----------------------------
# 종합 판단 + raw_evidence 문구(요구사항 반영)
# -----------------------------
if [ "${#VULN_DETAILS[@]}" -gt 0 ]; then
  STATUS="FAIL"
  REASON_LINE="inetd/xinetd/systemd에서 불필요한 RPC 서비스가 활성(설정 존재 또는 disable=no / enabled·active)되어 있어 취약합니다."
  DETAIL_CONTENT="$(printf "%s\n\n" "${VULN_DETAILS[@]}")"
  DETAIL_CONTENT="${DETAIL_CONTENT}조치: (1) inetd 사용 시 /etc/inetd.conf에서 해당 rpc 서비스 라인을 주석 처리 후 inetd 재시작, (2) xinetd 사용 시 /etc/xinetd.d/*에서 disable=yes로 변경 후 xinetd 재시작, (3) systemd 사용 시 불필요 유닛을 stop 후 disable 처리하십시오."
else
  STATUS="PASS"
  REASON_LINE="inetd(/etc/inetd.conf)·xinetd(/etc/xinetd.d)·systemd에서 가이드의 불필요 RPC 서비스 목록이 활성화된 설정(disable=no 또는 enabled/active)이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="no_unneeded_rpc_service_active"
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