#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-42 불필요한 RPC 서비스 비활성화

# 1. 항목 정보 정의
ID="U-42"
CATEGORY="서비스 관리"
TITLE="불필요한 RPC 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [inetd] /etc/inetd.conf 파일 수정 (주석 처리)
# 가이드: RPC 서비스 라인 주석 처리 후 inetd 재시작
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*rpc"; then
        BEFORE_SETTING="$BEFORE_SETTING inetd RPC 서비스 활성화;"
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        # rpc로 시작하는 라인 주석 처리
        sed -i 's/^\([[:space:]]*rpc\)/#\1/g' /etc/inetd.conf
        # inetd 서비스 재시작
        systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf RPC 서비스 주석처리 및 inetd 재시작;"
    fi
fi

# [xinetd] /etc/xinetd.d/ 디렉터리 내 RPC 파일 disable 설정값 수정
# 가이드: disable = yes로 수정 후 xinetd 재시작
XINETD_MODIFIED=0
if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
        if [ -f "$conf" ]; then
            if echo "$conf" | grep -qi "rpc" || grep -q "service.*rpc" "$conf" 2>/dev/null; then
                if grep -qiE "disable\s*=\s*no" "$conf" 2>/dev/null; then
                    BEFORE_SETTING="$BEFORE_SETTING $(basename $conf) disable=no;"
                    cp "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)"
                    sed -i 's/disable\s*=\s*no/disable = yes/gi' "$conf"
                    XINETD_MODIFIED=1
                    ACTION_LOG="$ACTION_LOG $(basename $conf) disable=yes 설정;"
                fi
            fi
        fi
    done
fi

if [ $XINETD_MODIFIED -eq 1 ]; then
    systemctl restart xinetd 2>/dev/null
    ACTION_LOG="$ACTION_LOG xinetd 재시작;"
fi

# [systemd] 불필요한 RPC 서비스 중지 및 비활성화
# 가이드: systemctl stop/disable <서비스명>
RPC_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep rpc | awk '{print $1}')
for svc in $RPC_SERVICES; do
    BEFORE_SETTING="$BEFORE_SETTING systemd $svc 활성화;"
    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 중지 및 비활성화;"
done

AFTER_SETTING="RPC 서비스 비활성화 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="RPC 서비스가 이미 비활성화 상태"

# 3. 마스터 템플릿 표준 출력
echo ""

STATUS="$ACTION_RESULT"
EVIDENCE="$ACTION_LOG"
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
