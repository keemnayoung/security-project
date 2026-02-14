#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
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

TARGET_FILE="/etc/inetd.conf /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec systemd"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" || echo "inetd_conf_not_found_or_no_r_services" ); ( for f in /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; done ) ; ( systemctl list-units --type=service 2>/dev/null | grep -E "(rlogin|rsh|rexec)" | awk "{print \$1}" )'

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
        DETAIL_LINES+="${INETD_HITS}"$'\n'
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

# [systemd] rlogin/rsh/rexec 유닛 존재(활성/로딩) 여부
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "(rlogin|rsh|rexec)" | awk '{print $1}' | head -n 20)
if [ -n "$SYSTEMD_SERVICES" ]; then
    VULNERABLE=1
    DETAIL_LINES+="systemd: r 계열 서비스 유닛이 로드/활성 상태로 확인됩니다."$'\n'
    DETAIL_LINES+="${SYSTEMD_SERVICES}"$'\n'
else
    DETAIL_LINES+="systemd: rlogin/rsh/rexec 서비스 유닛 로드/활성 내역 미확인."$'\n'
fi

# 최종 판정
if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="r 계열 서비스(rsh, rlogin, rexec 등)가 활성화되어 인증 없이 원격 접속 또는 신뢰 기반 접속이 가능해질 위험이 있으므로 취약합니다. 불필요한 r 계열 서비스는 비활성화해야 합니다."
else
    STATUS="PASS"
    REASON_LINE="r 계열 서비스(rsh, rlogin, rexec 등)가 활성화된 흔적이 확인되지 않아 인증 우회 기반 원격 접속 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
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