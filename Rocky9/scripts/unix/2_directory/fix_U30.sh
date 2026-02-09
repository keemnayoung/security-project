#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값 022 이상으로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-30"
CATEGORY="파일 및 디렉토리 관리"
TITLE="UMASK 설정 관리"
IMPORTANCE="중"

ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

PROFILE_OK=0
LOGIN_DEFS_OK=0


# 1. /etc/profile 조치
if [ -f /etc/profile ]; then
    cp -p /etc/profile /etc/profile_bak_"$(date +%Y%m%d_%H%M%S)"

    sed -i '/^[[:space:]]*umask[[:space:]]\+[0-9]\+/Id' /etc/profile
    echo -e "\numask 022\nexport umask" >> /etc/profile

    FINAL_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 1 | awk '{print $2}')
    [ "$FINAL_PROFILE" -ge 22 ] && PROFILE_OK=1
else
    ACTION_LOG="조치 실패: /etc/profile 파일 없음"
fi


# 2. /etc/login.defs 조치
if [ -f /etc/login.defs ]; then
    cp -p /etc/login.defs "/etc/login.defs_bak_$(date +%Y%m%d_%H%M%S)"

    sed -i '/^[[:space:]]*UMASK[[:space:]]\+[0-9]\+/Id' /etc/login.defs
    echo "UMASK 022" >> /etc/login.defs

    FINAL_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 1 | awk '{print $2}')
    [ "$FINAL_LOGIN_DEFS" -ge 22 ] && LOGIN_DEFS_OK=1
else
    ACTION_LOG="조치 실패: /etc/login.defs 파일 없음"
fi


# 3. 결과 판정
if [ "$PROFILE_OK" -eq 1 ] && [ "$LOGIN_DEFS_OK" -eq 1 ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="UMASK 설정 완료 (/etc/profile, /etc/login.defs 모두 022 이상 적용)"
    EVIDENCE="적용값 확인: /etc/profile=$FINAL_PROFILE, /etc/login.defs=$FINAL_LOGIN_DEFS (양호)"
elif [ "$PROFILE_OK" -eq 1 ] || [ "$LOGIN_DEFS_OK" -eq 1 ]; then
    ACTION_RESULT="PARTIAL_SUCCESS"
    STATUS="FAIL"
    ACTION_LOG="일부 파일에만 UMASK 설정 적용됨"
    EVIDENCE="적용값 확인: /etc/profile=${FINAL_PROFILE:-미설정}, /etc/login.defs=${FINAL_LOGIN_DEFS:-미설정} (취약)"
else
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    ACTION_LOG="UMASK 설정 조치 실패"
    EVIDENCE="UMASK 값이 022 이상으로 적용되지 않음"
fi


# 4. JSON 결과 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 UMASK 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF