#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정 해제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 검토 필요
#######################


ID="U-23"
CATEGORY="파일 및 디렉토리 관리"
TITLE="SUID, SGID, Sticky bit 설정 파일 점검"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 1. 실제 조치 프로세스 시작
SUID_SGID_FILES=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

if [ -z "$SUID_SGID_FILES" ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="SUID 또는 SGID가 설정된 불필요한 파일이 존재하지 않아 해당 항목에 보안 위협이 없습니다."
    EVIDENCE="SUID 또는 SGID가 설정된 불필요한 파일이 존재하지 않아 해당 항목에 보안 위협이 없습니다."
else
    # 조치 전 상태 기록
    BEFORE_LIST=$(echo "$SUID_SGID_FILES" | tr '\n' ',' | sed 's/,$//')

    # SUID / SGID 제거
    for FILE in $SUID_SGID_FILES; do
        chmod -s "$FILE" 2>/dev/null
        if [ $? -eq 0 ]; then
            ACTION_LOG+="${FILE}의 권한 제거가 완료되었습니다. "
        else
            ACTION_LOG+="${FILE}의 권한 제거가 실패하였습니다. "
        fi
    done

    # 재확인
    REMAIN_FILES=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

    if [ -z "$REMAIN_FILES" ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG+="모든 파일의 SUID 및 SGID 권한이 제거되었습니다."
        EVIDENCE="조치 전 상태: ${BEFORE_LIST} → 조치 후 상태: 미검출로 양호합니다."
        GUIDE="KISA 가이드라인에 따른 보안 설정이 완료되었습니다."
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        AFTER_LIST=$(echo "$REMAIN_FILES" | tr '\n' ',' | sed 's/,$//')
        ACTION_LOG+="일부 파일에서 권한 제거가 실패하였습니다."
        EVIDENCE="조치 후에도 SUID/SGID 유지됨: ${AFTER_LIST}로 여전히 취약합니다. 수동 확인이 필요합니다."
        GUIDE="불필요한 SUID, SGID 권한 또는 해당 파일을 제거하십시오. 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거해야 합니다."
    fi
fi

# 2. JSON 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF
