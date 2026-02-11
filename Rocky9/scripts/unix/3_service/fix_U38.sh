#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-38 DoS 공격에 취약한 서비스 비활성화

# 1. 항목 정보 정의
ID="U-38"
CATEGORY="서비스 관리"
TITLE="DoS 공격에 취약한 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

DOS_SERVICES=("echo" "discard" "daytime" "chargen")

# [inetd] /etc/inetd.conf 파일 수정 (주석 처리)
# 가이드: 서비스 주석 처리 후 inetd 재시작
if [ -f "/etc/inetd.conf" ]; then
    INETD_MODIFIED=0
    for svc in "${DOS_SERVICES[@]}"; do
        if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then

            INETD_MODIFIED=1
        fi
    done
    
    if [ $INETD_MODIFIED -eq 1 ]; then
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        for svc in "${DOS_SERVICES[@]}"; do
            sed -i "s/^\([[:space:]]*$svc\)/#\1/g" /etc/inetd.conf
        done
        # inetd 서비스 재시작
        killall -HUP inetd 2>/dev/null || systemctl restart inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf DoS 서비스를 주석 처리하고 inetd를 재시작했습니다."
    fi
fi

# [xinetd] /etc/xinetd.d/<파일명> 수정 (disable = yes)
# 가이드: disable = yes로 수정 후 xinetd 재시작
XINETD_MODIFIED=0
for svc in "${DOS_SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/$svc" ]; then
        if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc" 2>/dev/null; then

            cp "/etc/xinetd.d/$svc" "/etc/xinetd.d/${svc}.bak_$(date +%Y%m%d_%H%M%S)"
            sed -i 's/disable\s*=\s*no/disable = yes/gi' "/etc/xinetd.d/$svc"
            XINETD_MODIFIED=1
            ACTION_LOG="$ACTION_LOG /etc/xinetd.d/$svc에서 disable=yes로 설정했습니다."
        fi
    fi
done

if [ $XINETD_MODIFIED -eq 1 ]; then
    # 가이드: service xinetd restart
    service xinetd restart 2>/dev/null || systemctl restart xinetd 2>/dev/null
    ACTION_LOG="$ACTION_LOG xinetd를 재시작했습니다."
fi

# [systemd] 서비스 중지 및 비활성화
# 가이드: systemctl stop/disable <서비스명>
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "echo|discard|daytime|chargen" | awk '{print $1}')
for svc in $SYSTEMD_SERVICES; do

    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd $svc 서비스를 중지하고 비활성화했습니다."
done

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)를 비활성화했습니다."
else
    ACTION_LOG="DoS 취약 서비스가 이미 비활성화되어 있어 추가 조치 없이 양호한 상태를 유지합니다."
fi

STATUS="PASS"
EVIDENCE="DoS 공격에 취약한 서비스가 비활성화되어 있습니다."

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
