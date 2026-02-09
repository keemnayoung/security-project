#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값이 022 이상 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 점검 항목 정보 정의
CHECK_ID="U-30"
CATEGORY="파일 및 디렉토리 관리"
TITLE="UMASK 설정 관리"
IMPORTANCE="중"
STATUS="PASS"
EVIDENCE=""
TARGET_FILE="/etc/profile, /etc/login.defs"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 사용자나 그룹 간 파일 공유가 필요한 작업에서는 접근 권한 문제로 불편이 발생할 수 있습니다."
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

UMASK_PROFILE=""
UMASK_LOGIN_DEFS=""


# 2. 점검 로직

# /etc/profile 내 umask 설정 확인
if [ -f /etc/profile ]; then
    UMASK_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | awk '{print $2}' | tail -n 1)
fi

# /etc/login.defs 내 UMASK 설정 확인
if [ -f /etc/login.defs ]; then
    UMASK_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | awk '{print $2}' | tail -n 1)
fi

# UMASK 판단
CHECK_VALUES=()

[ -n "$UMASK_PROFILE" ] && CHECK_VALUES+=("$UMASK_PROFILE")
[ -n "$UMASK_LOGIN_DEFS" ] && CHECK_VALUES+=("$UMASK_LOGIN_DEFS")

if [ ${#CHECK_VALUES[@]} -eq 0 ]; then
    STATUS="FAIL"
    EVIDENCE="UMASK 설정이 /etc/profile 및 /etc/login.defs 파일에서 확인되지 않음"
else
    for VALUE in "${CHECK_VALUES[@]}"; do
        if [ "$VALUE" -lt 22 ]; then
            STATUS="FAIL"
            break
        fi
    done

    if [ "$STATUS" = "PASS" ]; then
        EVIDENCE="UMASK 값이 022 이상으로 설정됨 (/etc/profile: ${UMASK_PROFILE:-미설정}, /etc/login.defs: ${UMASK_LOGIN_DEFS:-미설정})"
    else
        EVIDENCE="UMASK 값이 022 미만으로 설정됨 (/etc/profile: ${UMASK_PROFILE:-미설정}, /etc/login.defs: ${UMASK_LOGIN_DEFS:-미설정})"
    fi
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "설정 파일에 UMASK 값을 022로 설정해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF