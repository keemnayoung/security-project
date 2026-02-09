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

ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG=""
EVIDENCE=""

# 1. 실제 조치 프로세스 시작
SUID_SGID_FILES=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

if [ -z "$SUID_SGID_FILES" ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="SUID 또는 SGID가 설정된 불필요한 파일이 존재하지 않습니다."
    EVIDENCE="SUID/SGID 설정 파일 미검출 (양호)"
else
    # 조치 전 상태 기록
    BEFORE_LIST=$(echo "$SUID_SGID_FILES" | tr '\n' ',' | sed 's/,$//')

    # SUID / SGID 제거
    for FILE in $SUID_SGID_FILES; do
        chmod -s "$FILE" 2>/dev/null
        if [ $? -eq 0 ]; then
            ACTION_LOG="${ACTION_LOG}권한 제거 완료: ${FILE}, "
        else
            ACTION_LOG="${ACTION_LOG}권한 제거 실패: ${FILE}, "
        fi
    done

    # 재확인
    REMAIN_FILES=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

    if [ -z "$REMAIN_FILES" ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="${ACTION_LOG}모든 SUID/SGID 권한 제거 완료"
        EVIDENCE="조치 전: ${BEFORE_LIST} → 조치 후: 미검출 (양호)"
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        AFTER_LIST=$(echo "$REMAIN_FILES" | tr '\n' ',' | sed 's/,$//')
        ACTION_LOG="${ACTION_LOG}일부 파일에서 권한 제거 실패"
        EVIDENCE="조치 후에도 SUID/SGID 유지됨: ${AFTER_LIST} (취약)"
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
    "guide": "KISA 가이드라인에 따라 불필요한 SUID/SGID 권한을 제거하도록 설정했습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
