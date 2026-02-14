#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-34 Finger 서비스 비활성화

ID="U-34"
CATEGORY="서비스 관리"
TITLE="Finger 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

ACTION_RESULT="SUCCESS"
ACTION_LOG=""

append_log() {
    if [ -n "$ACTION_LOG" ]; then
        ACTION_LOG="$ACTION_LOG; $1"
    else
        ACTION_LOG="$1"
    fi
}

restart_if_exists() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\\.service" || return 0
    systemctl restart "$svc" 2>/dev/null || true
}

# [inetd] /etc/inetd.conf에서 finger 주석 처리
if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
        cp -a /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)"
        sed -i 's/^\([[:space:]]*finger\)/#\1/g' /etc/inetd.conf
        append_log "/etc/inetd.conf에서 finger 라인을 주석 처리했습니다."
        restart_if_exists inetd
    fi
fi

# [xinetd] /etc/xinetd.d/finger의 disable 옵션을 yes로 수정
# 주의: sed에서 \\s 는 동작하지 않으므로(기본 정규식) POSIX 문자 클래스를 사용합니다.
if [ -f "/etc/xinetd.d/finger" ]; then
    TARGET_FILE="/etc/xinetd.d/finger"
    if grep -Ev "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        cp -a /etc/xinetd.d/finger "/etc/xinetd.d/finger.bak_$(date +%Y%m%d_%H%M%S)"
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' /etc/xinetd.d/finger
        append_log "/etc/xinetd.d/finger의 disable=no를 disable=yes로 변경했습니다."
        restart_if_exists xinetd
    fi
fi

# [검증] 조치 후 실제 적용 상태 확인
FINGER_STILL=0
if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
        FINGER_STILL=1
    fi
fi
if [ -f "/etc/xinetd.d/finger" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        FINGER_STILL=1
    fi
fi

if [ $FINGER_STILL -eq 0 ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="${ACTION_LOG:-Finger 서비스가 이미 비활성화되어 있습니다.}"
    EVIDENCE="Finger 서비스가 비활성화되어 있습니다."
else
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    ACTION_LOG="${ACTION_LOG:-} Finger 서비스 비활성화를 시도했으나 일부 설정이 여전히 활성화 상태입니다. 수동 확인이 필요합니다."
    EVIDENCE="Finger 서비스가 여전히 활성화되어 있어 취약합니다."
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "xinetd에서 finger 서비스를 disable=yes로 설정하거나, inetd.conf에서 finger 라인을 주석처리 후 서비스를 재시작해야 합니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
