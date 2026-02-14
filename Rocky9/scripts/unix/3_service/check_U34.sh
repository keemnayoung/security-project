#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 점검
# @Criteria_Good : Finger 서비스가 비활성화된 경우
# @Criteria_Bad : Finger 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-34 Finger 서비스 비활성화

# 기본 변수
ID="U-34"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/inetd.conf /etc/xinetd.d/finger"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || echo "inetd_finger_not_found_or_commented" ); ( [ -f /etc/xinetd.d/finger ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" || echo "xinetd_finger_disable_no_not_found_or_file_missing" )'

REASON_LINE=""
DETAIL_CONTENT=""

FINGER_ACTIVE=0
DETAIL_LINES=""

# inetd 기반 점검
if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/inetd.conf" 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
        FINGER_ACTIVE=1
        DETAIL_LINES+="/etc/inetd.conf: finger 서비스 라인이 주석 처리되지 않고 활성화되어 있습니다."$'\n'
    else
        DETAIL_LINES+="/etc/inetd.conf: finger 서비스 활성 라인 미확인(없음 또는 주석 처리됨)."$'\n'
    fi
else
    DETAIL_LINES+="/etc/inetd.conf: 파일이 존재하지 않습니다."$'\n'
fi

# xinetd 기반 점검
if [ -f "/etc/xinetd.d/finger" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/finger" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        FINGER_ACTIVE=1
        DETAIL_LINES+="/etc/xinetd.d/finger: disable = no 로 설정되어 서비스가 활성화되어 있습니다."$'\n'
    else
        # disable=yes, 또는 disable 미설정/주석 등은 여기서 '취약 근거'로 확정하지 않고 현 상태를 출력
        CUR_DISABLE=$(grep -Ev '^[[:space:]]*#' "/etc/xinetd.d/finger" 2>/dev/null | grep -iE '^[[:space:]]*disable[[:space:]]*=' | tail -n 1 | sed 's/[[:space:]]//g')
        if [ -n "$CUR_DISABLE" ]; then
            DETAIL_LINES+="/etc/xinetd.d/finger: ${CUR_DISABLE} (disable=no 미확인)."$'\n'
        else
            DETAIL_LINES+="/etc/xinetd.d/finger: disable 설정 라인 미확인(없음 또는 주석 처리됨)."$'\n'
        fi
    fi
else
    DETAIL_LINES+="/etc/xinetd.d/finger: 파일이 존재하지 않습니다."$'\n'
fi

# 최종 판정
if [ "$FINGER_ACTIVE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="Finger 서비스가 활성화되어 있어 외부에서 시스템 사용자 정보가 노출될 수 있으므로 취약합니다. finger 서비스를 비활성화(inetd에서는 finger 라인 주석 처리, xinetd에서는 disable=yes 설정)해야 합니다."
else
    STATUS="PASS"
    REASON_LINE="Finger 서비스가 inetd/xinetd 설정에서 활성화되어 있지 않아 외부에서 시스템 사용자 정보가 노출될 가능성이 없으므로 이 항목에 대한 보안 위협이 없습니다."
fi

# detail(줄바꿈 유지, 소유자/권한은 한 줄 규칙 해당 없음)
DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

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