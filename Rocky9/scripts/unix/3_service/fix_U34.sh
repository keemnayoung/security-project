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
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-34 Finger 서비스 비활성화

# 1. 항목 정보 정의
ID="U-34"
CATEGORY="서비스 관리"
TITLE="Finger 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/xinetd.d/finger"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [inetd] /etc/inetd.conf에서 finger 주석 처리
# 가이드: finger 서비스 항목 주석 처리 후 inetd 서비스 재시작
if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/^\([[:space:]]*finger\)/#\1/g' /etc/inetd.conf
        if command -v systemctl &>/dev/null; then
            systemctl restart inetd 2>/dev/null
        else
            killall -HUP inetd 2>/dev/null
        fi
    fi
fi

# [xinetd] /etc/xinetd.d/finger의 disable 옵션을 yes로 수정
# 가이드: disable = yes로 수정 후 xinetd 서비스 재시작
if [ -f "/etc/xinetd.d/finger" ]; then
    # disable = no (대소문자 무시, 공백 무시) 확인
    if grep -Ev "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        cp /etc/xinetd.d/finger /etc/xinetd.d/finger.bak_$(date +%Y%m%d_%H%M%S)
        # disable=no를 disable=yes로 변경 (공백/대소문자/인라인 주석 케이스 대응)
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' /etc/xinetd.d/finger
        systemctl restart xinetd 2>/dev/null
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
    ACTION_LOG="Finger 서비스의 설정 파일을 수정하여 서비스를 비활성화했습니다."
    EVIDENCE="Finger 서비스가 비활성화되어 있습니다."
else
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    ACTION_LOG="Finger 서비스 비활성화를 시도했으나 일부 설정이 여전히 활성화 상태입니다. 수동 확인이 필요합니다."
    EVIDENCE="Finger 서비스가 여전히 활성화되어 있어 취약합니다."
fi

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
