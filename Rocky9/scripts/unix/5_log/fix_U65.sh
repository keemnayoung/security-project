#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-08
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-65
# @Category    : 로그 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 및 시각 동기화 설정이 기준에 따라 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 기본 변수 정의
ID="U-65"
TARGET_FILE=""
ACTION_RESULT="FAIL"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

DEFAULT_NTP_SERVER="time.google.com"


# 2. 서비스 활성화 여부
USE_NTP=false

if systemctl list-units --type=service | grep -q chrony; then
    USE_CHRONY=true
elif systemctl list-units --type=service | grep -q ntp; then
    USE_NTP=true
fi


# 3. Chrony 조치
if [ "$USE_CHRONY" = true ]; then
    TARGET_FILE="/etc/chrony.conf"
    ACTION_LOG+="Chrony 기반 조치 수행, "

    # 사전 상태 수집
    if systemctl list-units --type=service | grep -q chrony; then
        BEFORE_SETTING+="chrony=active, "
    else
        BEFORE_SETTING+="chrony=inactive, "
    fi

    # 설정 파일 서버 항목 확인 및 추가
    if ! grep -qE '^[[:space:]]*server[[:space:]]+' "$TARGET_FILE" 2>/dev/null; then
        echo "server $DEFAULT_NTP_SERVER iburst" >> "$TARGET_FILE"
        ACTION_LOG+="chrony.conf 서버 추가($DEFAULT_NTP_SERVER), "
    else
        ACTION_LOG+="chrony.conf 서버 설정 이미 존재, "
    fi

    # 서비스 재시작
    systemctl restart chrony
    sleep 2

    # 사후 상태 수집
    if systemctl list-units --type=service | grep -q chrony; then
        AFTER_SETTING+="chrony=active, "
    else
        AFTER_SETTING+="chrony=inactive, "
    fi

    # 동기화 확인
    if command -v chronyc >/dev/null 2>&1 && chronyc sources 2>/dev/null | grep -q '^\^'; then
        AFTER_SETTING+="sync=ok"
        ACTION_RESULT="PASS"
    else
        AFTER_SETTING+="sync=fail"
    fi
fi



# 4. NTP 조치
if [ "$USE_NTP" = true ] && [ "$USE_CHRONY" = false ]; then
    TARGET_FILE="/etc/ntp.conf"
    ACTION_LOG+="NTP 기반 조치 수행, "

    # 사전 상태 수집
    if systemctl list-units --type=service | grep -q ntp; then
        BEFORE_SETTING+="ntp=active, "
    else
        BEFORE_SETTING+="ntp=inactive, "
    fi

    # 설정 파일 서버 항목 확인 및 추가
    if ! grep -qE '^[[:space:]]*server[[:space:]]+' "$TARGET_FILE" 2>/dev/null; then
        echo "server $DEFAULT_NTP_SERVER" >> "$TARGET_FILE"
        ACTION_LOG+="ntp.conf 서버 추가($DEFAULT_NTP_SERVER), "
    else
        ACTION_LOG+="ntp.conf 서버 설정 이미 존재, "
    fi

    # 서비스 재시작
    systemctl restart ntp
    sleep 2

    # 사후 상태 수집
    if systemctl list-units --type=service | grep -q ntp; then
        AFTER_SETTING+="ntp=active, "
    else
        AFTER_SETTING+="ntp=inactive, "
    fi

    # 동기화 확인
    if command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | grep -q '^[\*\+]'; then
        AFTER_SETTING+="sync=ok"
        ACTION_RESULT="PASS"
    else
        AFTER_SETTING+="sync=fail"
    fi
fi


# 5. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF