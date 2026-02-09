#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk 서비스를 비활성화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-44 tftp, talk 서비스 비활성화

# 1. 항목 정보 정의
ID="U-44"
CATEGORY="서비스관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

SERVICES=("tftp" "talk" "ntalk")

# [inetd] /etc/inetd.conf 파일 수정 (주석 처리)
# 가이드: rpc.cmsd 등 서비스 주석 처리 후 inetd 재시작
if [ -f "/etc/inetd.conf" ]; then
    INETD_MODIFIED=0
    for svc in "${SERVICES[@]}"; do
        if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then
            BEFORE_SETTING="$BEFORE_SETTING inetd $svc 활성화;"
            INETD_MODIFIED=1
        fi
    done
    
    if [ $INETD_MODIFIED -eq 1 ]; then
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        for svc in "${SERVICES[@]}"; do
            sed -i "s/^\([[:space:]]*$svc\)/#\1/g" /etc/inetd.conf
        done
        # inetd 서비스 재시작
        systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf tftp/talk 주석처리 및 inetd 재시작;"
    fi
fi

# [xinetd] /etc/xinetd.d/ 디렉터리 내 서비스 비활성화
# 가이드: disable = yes로 수정 후 xinetd 재시작
XINETD_MODIFIED=0
if [ -d "/etc/xinetd.d" ]; then
    for svc in "${SERVICES[@]}"; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc" 2>/dev/null; then
                BEFORE_SETTING="$BEFORE_SETTING xinetd $svc disable=no;"
                cp "/etc/xinetd.d/$svc" "/etc/xinetd.d/${svc}.bak_$(date +%Y%m%d_%H%M%S)"
                sed -i 's/disable\s*=\s*no/disable = yes/gi' "/etc/xinetd.d/$svc"
                XINETD_MODIFIED=1
                ACTION_LOG="$ACTION_LOG /etc/xinetd.d/$svc disable=yes 설정;"
            fi
        fi
    done
fi

if [ $XINETD_MODIFIED -eq 1 ]; then
    systemctl restart xinetd 2>/dev/null
    ACTION_LOG="$ACTION_LOG xinetd 재시작;"
fi

# [systemd] 서비스 중지 및 비활성화
# 가이드: systemctl stop/disable <서비스명>
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "tftp|talk|ntalk" | awk '{print $1}')
for svc in $SYSTEMD_SERVICES; do
    BEFORE_SETTING="$BEFORE_SETTING systemd $svc 활성화;"
    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 중지 및 비활성화;"
done

AFTER_SETTING="tftp, talk 서비스 비활성화 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="tftp, talk 서비스가 이미 비활성화 상태"

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
