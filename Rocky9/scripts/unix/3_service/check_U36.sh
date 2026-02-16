#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : r-command 서비스 비활성화 여부 점검
# @Criteria_Good : 불필요한 r 계열 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 r 계열 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-36 r 계열 서비스 비활성화

# 기본 변수
ID="U-36"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/inetd.conf /etc/xinetd.d/(rsh|rlogin|rexec|shell|login|exec) systemd(unit/service/socket) /etc/hosts.equiv /home/*/.rhosts"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" || echo "inetd_conf_not_found_or_no_r_services" ); ( for f in /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && echo "xinetd_disable_no:$f"; done ); ( systemctl list-units --type=service --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.service" | awk "{print \$1}" ); ( systemctl list-units --type=socket --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.socket" | awk "{print \$1}" ); ( systemctl list-unit-files 2>/dev/null | grep -E "^(rlogin|rsh|rexec|shell|login|exec)\.(service|socket)[[:space:]]+" || echo "no_r_unit_files" ); ( [ -f /etc/hosts.equiv ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv || echo "hosts_equiv_not_found_or_empty" ); ( find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null -print -exec sh -c '"'"'grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$1" >/dev/null 2>&1 && echo "rhosts_has_entries:$1" || echo "rhosts_empty_or_commented:$1"'"'"' _ {} \; 2>/dev/null || echo "no_rhosts_found" )'

DETAIL_CONTENT=""
REASON_LINE=""

VULNERABLE=0
DETAIL_LINES=""

R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

# [inetd] /etc/inetd.conf 내 r 계열 서비스 활성화 여부(주석 제외)
if [ -f "/etc/inetd.conf" ]; then
  INETD_HITS=$(grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)")
  if [ -n "$INETD_HITS" ]; then
    VULNERABLE=1
    DETAIL_LINES+="/etc/inetd.conf: r 계열 서비스 항목이 주석 없이 존재합니다(활성 가능)."$'\n'
    DETAIL_LINES+="$INETD_HITS"$'\n'
  else
    DETAIL_LINES+="/etc/inetd.conf: r 계열 서비스 활성 라인 미확인."$'\n'
  fi
else
  DETAIL_LINES+="/etc/inetd.conf: 파일이 존재하지 않습니다."$'\n'
fi

# [xinetd] /etc/xinetd.d/<svc> 내 disable=no 여부
for svc in "${R_SERVICES[@]}"; do
  XFILE="/etc/xinetd.d/${svc}"
  if [ -f "$XFILE" ]; then
    X_HIT=$(grep -nEv "^[[:space:]]*#" "$XFILE" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" | head -n 1)
    if [ -n "$X_HIT" ]; then
      VULNERABLE=1
      DETAIL_LINES+="${XFILE}: disable=no 로 설정되어 서비스가 활성 상태입니다. (${X_HIT})"$'\n'
    else
      DETAIL_LINES+="${XFILE}: disable=no 설정 미확인(비활성 또는 설정 없음)."$'\n'
    fi
  else
    DETAIL_LINES+="${XFILE}: 파일이 존재하지 않습니다."$'\n'
  fi
done

# [systemd] r 계열이 service/socket으로 로드/활성 또는 enabled 여부
SYSTEMD_ACTIVE_SVC=$(systemctl list-units --type=service --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.service" | awk '{print $1}' | head -n 50)
SYSTEMD_ACTIVE_SOCK=$(systemctl list-units --type=socket  --all 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell|login|exec)\.socket"  | awk '{print $1}' | head -n 50)
SYSTEMD_ENABLED=$(systemctl list-unit-files 2>/dev/null | awk '$1 ~ /^(rlogin|rsh|rexec|shell|login|exec)\.(service|socket)$/ {print $1" "$2}' | head -n 50)

if [ -n "$SYSTEMD_ACTIVE_SVC" ] || [ -n "$SYSTEMD_ACTIVE_SOCK" ] || [ -n "$SYSTEMD_ENABLED" ]; then
  # “존재만”이 아니라 활성/enable 단서가 있으면 취약 처리
  if [ -n "$SYSTEMD_ACTIVE_SVC" ] || [ -n "$SYSTEMD_ACTIVE_SOCK" ]; then
    VULNERABLE=1
    DETAIL_LINES+="systemd: r 계열 service/socket 유닛이 로드/활성 상태로 확인됩니다."$'\n'
    [ -n "$SYSTEMD_ACTIVE_SVC" ] && DETAIL_LINES+="$SYSTEMD_ACTIVE_SVC"$'\n'
    [ -n "$SYSTEMD_ACTIVE_SOCK" ] && DETAIL_LINES+="$SYSTEMD_ACTIVE_SOCK"$'\n'
  else
    DETAIL_LINES+="systemd: r 계열 service/socket 유닛이 활성으로 로드되진 않았으나 unit-files가 존재합니다."$'\n'
  fi

  # enabled 상태가 있으면 취약 단서(운영 정책상 disable 권장)
  if echo "$SYSTEMD_ENABLED" | grep -qE '[[:space:]]+(enabled|enabled-runtime)'; then
    VULNERABLE=1
    DETAIL_LINES+="systemd: r 계열 유닛이 enabled 상태로 확인됩니다."$'\n'
    DETAIL_LINES+="$SYSTEMD_ENABLED"$'\n'
  else
    DETAIL_LINES+="systemd: r 계열 유닛 enabled 상태 미확인(또는 disabled/static)."${SYSTEMD_ENABLED:+$'\n'"$SYSTEMD_ENABLED"}$'\n'
  fi
else
  DETAIL_LINES+="systemd: r 계열(service/socket) 관련 유닛/설정 내역 미확인."$'\n'
fi

# [신뢰 기반 접속 설정] /etc/hosts.equiv 및 /home/*/.rhosts 존재/내용 확인
TRUST_FOUND=0

if [ -f "/etc/hosts.equiv" ]; then
  HOSTS_EQ=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv 2>/dev/null | head -n 20)
  if [ -n "$HOSTS_EQ" ]; then
    TRUST_FOUND=1
    DETAIL_LINES+="/etc/hosts.equiv: 주석/공백이 아닌 설정이 존재합니다(신뢰 기반 접속 가능성)."$'\n'
    DETAIL_LINES+="$HOSTS_EQ"$'\n'
  else
    DETAIL_LINES+="/etc/hosts.equiv: 유효 설정(주석/공백 제외) 미확인."$'\n'
  fi
else
  DETAIL_LINES+="/etc/hosts.equiv: 파일이 존재하지 않습니다."$'\n'
fi

RHOSTS_LIST=$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 20)
if [ -n "$RHOSTS_LIST" ]; then
  # 내용이 있는 rhosts가 하나라도 있으면 위험 단서
  while IFS= read -r rf; do
    RHOSTS_BODY=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$rf" 2>/dev/null | head -n 5)
    if [ -n "$RHOSTS_BODY" ]; then
      TRUST_FOUND=1
      DETAIL_LINES+="${rf}: 주석/공백이 아닌 설정이 존재합니다(신뢰 기반 접속 가능성)."$'\n'
      DETAIL_LINES+="$RHOSTS_BODY"$'\n'
    else
      DETAIL_LINES+="${rf}: 유효 설정(주석/공백 제외) 미확인."$'\n'
    fi
  done <<< "$RHOSTS_LIST"
else
  DETAIL_LINES+="/home/*/.rhosts: 파일이 존재하지 않습니다."$'\n'
fi

# U-36의 핵심은 “r 계열 서비스 비활성화”이므로,
# trust 파일은 "사용 여부/위험 단서"로 detail에 포함하되,
# 서비스가 실제로 활성 단서가 있으면 VULNERABLE을 우선적으로 FAIL 처리.
# (다만 trust 파일만 있어도 운영 정책에 따라 제거 권고가 필요하므로 FAIL 단서로 포함)
if [ "$TRUST_FOUND" -eq 1 ]; then
  VULNERABLE=1
fi

# 최종 판정 + 문구(요구사항 반영: 양호/취약 문장 + 간단 조치)
if [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="점검 결과, /etc/inetd.conf 또는 /etc/xinetd.d 설정에서 r 계열 서비스가 활성(disable=no 또는 활성 라인 존재)되었거나 systemd에서 r 계열 service/socket이 로드/활성(enabled 포함)되어 있거나, /etc/hosts.equiv 및 /home/*/.rhosts에 신뢰 기반 설정이 존재하여 취약합니다. 조치: (1) inetd 사용 시 /etc/inetd.conf의 rsh/rlogin/rexec/shell/login/exec 항목을 주석/삭제 후 inetd 재시작 (2) xinetd 사용 시 /etc/xinetd.d/*에서 disable=yes로 변경 후 xinetd 재시작 (3) systemd 사용 시 관련 service/socket을 stop 후 disable (예: systemctl disable --now rsh.socket 등) (4) 불필요 시 /etc/hosts.equiv 및 .rhosts 설정 제거/비활성화를 수행하십시오."
else
  STATUS="PASS"
  REASON_LINE="점검 결과, /etc/inetd.conf에 r 계열 서비스 활성 라인이 없고 /etc/xinetd.d/*에 disable=no 설정이 없으며, systemd에서도 r 해당 service/socket이 로드/활성(enabled 포함)되지 않고, /etc/hosts.equiv 및 /home/*/.rhosts에 유효한 신뢰 기반 설정이 없어 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

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