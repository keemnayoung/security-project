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

# 1. 항목 정보 정의
ID="U-36"
CATEGORY="서비스 관리"
TITLE="r 계열 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")
DETAILS=()

add_detail() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    DETAILS+=("$msg")
}

# [inetd] /etc/inetd.conf 파일 내 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: 주석 처리되지 않은 r 계열 서비스 확인
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    for svc in "${R_SERVICES[@]}"; do
        if grep -Ev "^[[:space:]]*#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
            VULNERABLE=1
            add_detail "/etc/inetd.conf에서 ${svc} 서비스가 활성화되어 있습니다"
        fi
    done
fi

# [xinetd] /etc/xinetd.d/<파일> 내 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: disable = no인 경우 취약
for svc in "${R_SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/$svc" ]; then
        TARGET_FILE="/etc/xinetd.d/$svc"
        if grep -Ev "^[[:space:]]*#" "$TARGET_FILE" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
            VULNERABLE=1
            add_detail "/etc/xinetd.d/${svc}에서 disable=no로 설정되어 있습니다"
        fi
    fi
done

# [systemd] 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: # systemctl list-units --type=service | grep -E "rlogin|rsh|rexec"
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "rlogin|rsh|rexec" | awk '{print $1}')
if [ -n "$SYSTEMD_SERVICES" ]; then
    VULNERABLE=1
    add_detail "systemd에서 r 계열 서비스가 활성화되어 있습니다(${SYSTEMD_SERVICES})"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="r 계열 서비스(rsh, rlogin, rexec)가 활성화되어 인증 없이 원격 접속이 가능한 위험이 있습니다."
else
    STATUS="PASS"
    EVIDENCE="r 계열 서비스가 비활성화되어 있습니다."
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, r-command 서비스가 백업 또는 클러스터링 등 특정 용도로 사용 중인 환경이라면 관련 작업이 중단될 수 있으므로 적용 전 서비스 사용 여부와 대체 수단을 반드시 확인해야 합니다."

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "xinetd에서 rsh, rlogin, rexec 서비스를 disable=yes로 설정하고, /etc/hosts.equiv 및 .rhosts 파일을 삭제해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
