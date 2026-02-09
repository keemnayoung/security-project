#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-34
# @Category : Service
# @Platform : Debian
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스를 비활성화하여 보안 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-34 Finger 서비스 비활성화

# 1. 항목 정보 정의
ID="U-34"
CATEGORY="서비스관리"
TITLE="Finger 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/xinetd.d/finger"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [inetd] /etc/inetd.conf에서 finger 주석 처리
# 가이드: finger 서비스 항목 주석 처리 후 inetd 서비스 재시작
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger"; then
        BEFORE_SETTING="$BEFORE_SETTING inetd finger 활성화;"
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        # finger로 시작하는 라인 주석 처리
        sed -i 's/^\([[:space:]]*finger\)/#\1/g' /etc/inetd.conf
        # inetd 서비스 재시작
        if command -v systemctl &>/dev/null; then
            systemctl restart inetd 2>/dev/null
        else
            killall -HUP inetd 2>/dev/null
        fi
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf finger 주석처리 및 inetd 재시작;"
    fi
fi

# [xinetd] /etc/xinetd.d/finger의 disable 옵션을 yes로 수정
# 가이드: disable = yes로 수정 후 xinetd 서비스 재시작
if [ -f "/etc/xinetd.d/finger" ]; then
    if grep -qiE "disable\s*=\s*no" /etc/xinetd.d/finger 2>/dev/null; then
        BEFORE_SETTING="$BEFORE_SETTING xinetd finger disable=no;"
        cp /etc/xinetd.d/finger /etc/xinetd.d/finger.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/disable\s*=\s*no/disable = yes/g' /etc/xinetd.d/finger
        # xinetd 서비스 재시작
        systemctl restart xinetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/xinetd.d/finger disable=yes 설정 및 xinetd 재시작;"
    fi
fi

AFTER_SETTING="Finger 서비스 비활성화 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="Finger 서비스가 이미 비활성화 상태"

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
