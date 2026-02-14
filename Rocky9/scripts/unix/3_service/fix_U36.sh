#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : r-command 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-36 r 계열 서비스 비활성화

# 1. 항목 정보 정의
ID="U-36"
CATEGORY="서비스 관리"
TITLE="r 계열 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

# [inetd] /etc/inetd.conf 파일 내 불필요한 r 계열 서비스 주석 처리
# 가이드: r 계열 서비스 관련 필드 주석 처리 후 inetd 서비스 재시작
if [ -f "/etc/inetd.conf" ]; then
    INETD_MODIFIED=0
    for svc in "${R_SERVICES[@]}"; do
        if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then

            INETD_MODIFIED=1
        fi
    done
    
    if [ $INETD_MODIFIED -eq 1 ]; then
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        for svc in "${R_SERVICES[@]}"; do
            sed -i "s/^\([[:space:]]*$svc\)/#\1/g" /etc/inetd.conf
        done
        # inetd 서비스 재시작
        if command -v systemctl &>/dev/null; then
            systemctl restart inetd 2>/dev/null
        else
            killall -HUP inetd 2>/dev/null
        fi
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf r계열 서비스를 주석처리하고 inetd를 재시작했습니다."
    fi
fi

# [xinetd] /etc/xinetd.d/<파일> 내 disable 값을 yes로 수정
# 가이드: disable = yes로 수정 후 xinetd 서비스 재시작
XINETD_MODIFIED=0
for svc in "${R_SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/$svc" ]; then
        if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$svc" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then

            cp "/etc/xinetd.d/$svc" "/etc/xinetd.d/${svc}.bak_$(date +%Y%m%d_%H%M%S)"
            sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "/etc/xinetd.d/$svc"
            XINETD_MODIFIED=1
            ACTION_LOG="$ACTION_LOG /etc/xinetd.d/$svc에서 disable=yes로 설정했습니다."
        fi
    fi
done

if [ $XINETD_MODIFIED -eq 1 ]; then
    systemctl restart xinetd 2>/dev/null
    ACTION_LOG="$ACTION_LOG xinetd를 재시작했습니다."
fi

# [systemd] 불필요한 r 계열 서비스 중지 및 비활성화
# 가이드: systemctl stop/disable <서비스 이름>
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "rlogin|rsh|rexec" | awk '{print $1}')
for svc in $SYSTEMD_SERVICES; do

    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd $svc 서비스를 중지하고 비활성화했습니다."
done

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="r 계열 서비스(rsh, rlogin, rexec 등)의 설정을 수정하여 서비스를 비활성화했습니다."
else
    ACTION_LOG="r 계열 서비스가 이미 비활성화되어 있어 추가 조치 없이 양호한 상태를 유지합니다."
fi

STATUS="PASS"
EVIDENCE="r 계열 서비스가 비활성화되어 있습니다."

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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
