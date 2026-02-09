#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값 022 이상으로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 변수 정의
CHECK_ID="U-30"
TARGET_FILE="/etc/profile, /etc/login.defs"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

BEFORE_SETTING=""
AFTER_SETTING=""


# 2. BEFORE 설정 수집
if [ -f /etc/profile ]; then
    BEFORE_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 1)
else
    BEFORE_PROFILE="파일 없음"
fi

if [ -f /etc/login.defs ]; then
    BEFORE_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 1)
else
    BEFORE_LOGIN_DEFS="파일 없음"
fi

BEFORE_SETTING="/etc/profile: ${BEFORE_PROFILE:-미설정}, /etc/login.defs: ${BEFORE_LOGIN_DEFS:-미설정}"


# 3. 조치 로직
# /etc/profile 조치
if [ -f /etc/profile ]; then
    cp -p /etc/profile /etc/profile.bak_$(date +%Y%m%d%H%M%S)

    if grep -qiE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile; then
        sed -i -E 's/^[[:space:]]*umask[[:space:]]+[0-9]+/umask 022/i' /etc/profile
        ACTION_LOG+="[/etc/profile] 기존 umask 설정을 022로 수정; "
    else
        echo -e "\numask 022\nexport umask" >> /etc/profile
        ACTION_LOG+="[/etc/profile] umask 022 설정 추가; "
    fi
else
    ACTION_RESULT="FAIL"
    ACTION_LOG+="[/etc/profile] 파일이 존재하지 않음; "
fi

# /etc/login.defs 조치
if [ -f /etc/login.defs ]; then
    cp -p /etc/login.defs /etc/login.defs.bak_$(date +%Y%m%d%H%M%S)

    if grep -qiE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs; then
        sed -i -E 's/^[[:space:]]*UMASK[[:space:]]+[0-9]+/UMASK 022/i' /etc/login.defs
        ACTION_LOG+="[/etc/login.defs] 기존 UMASK 설정을 022로 수정; "
    else
        echo -e "\nUMASK 022" >> /etc/login.defs
        ACTION_LOG+="[/etc/login.defs] UMASK 022 설정 추가; "
    fi
else
    ACTION_RESULT="FAIL"
    ACTION_LOG+="[/etc/login.defs] 파일이 존재하지 않음; "
fi


# 4. AFTER 설정 수집
AFTER_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 1 2>/dev/null)
AFTER_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 1 2>/dev/null)

AFTER_SETTING="/etc/profile: ${AFTER_PROFILE:-미설정}, /etc/login.defs: ${AFTER_LOGIN_DEFS:-미설정}"


# 5. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF