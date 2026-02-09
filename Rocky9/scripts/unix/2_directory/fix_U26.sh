#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#####################
# 검토 필요
#####################

# 0. 기본 변수 정의
ID="U-26"
CATEGORY="파일 및 디렉터리 관리"
TITLE="/dev에 존재하지 않는 device 파일 점검"
IMPORTANCE="상"
TARGET_FILE="/dev"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

ACTION_DATE=$(date "+%Y-%m-%d %H:%M:%S")
CHECK_DATE=$(date "+%Y-%m-%d %H:%M:%S")


# 1. 실제 조치 프로세스 시작
if [ -d "$TARGET_FILE" ]; then

    # 1-1. 불필요한 일반 파일 탐색
    INVALID_FILES=$(find /dev -type f 2>/dev/null)

    if [ -z "$INVALID_FILES" ]; then
        # 이미 양호한 상태
        STATUS="PASS"
        ACTION_RESULT="NO_ACTION_REQUIRED"
        ACTION_LOG="조치 대상 파일이 존재하지 않아 추가 조치가 필요하지 않습니다."
        EVIDENCE="불필요하거나 존재하지 않는 device 파일 없음 (양호)"
    else
        # 쉼표 구분 문자열 생성
        INVALID_FILES_CSV=$(echo "$INVALID_FILES" | paste -sd ", " -)

        # 1-2. 삭제 수행
        rm -f $INVALID_FILES 2>/dev/null

        # 1-3. 삭제 후 재검증
        REMAIN_FILES=$(find /dev -type f 2>/dev/null)

        if [ -z "$REMAIN_FILES" ]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="불필요하거나 존재하지 않는 device 파일 삭제 완료"
            EVIDENCE="삭제된 파일: $INVALID_FILES_CSV (양호)"
        else
            REMAIN_FILES_CSV=$(echo "$REMAIN_FILES" | paste -sd ", " -)
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="일부 device 파일 삭제 실패. 수동 확인 필요"
            EVIDENCE="잔존 파일: $REMAIN_FILES_CSV (취약)"
        fi
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="/dev 디렉터리가 존재하지 않습니다."
    EVIDENCE="조치 대상 디렉터리 없음"
fi


# 2. JSON 표준 출력
echo ""

cat <<EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "/dev 디렉터리는 character/block device 파일만 존재해야 하며, 일반 파일은 제거되어야 합니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF