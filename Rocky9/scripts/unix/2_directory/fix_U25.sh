#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : world writable 권한 제거 (chmod o-w)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

###################
# 검토 필요
###################

ID="U-25"
CATEGORY="파일 및 디렉토리 관리"
TITLE="world writable 파일 점검"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE="KISA 가이드라인에 따른 홈 디렉터리 환경변수 파일 권한 설정을 수행하였습니다."
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TMP_BEFORE="/tmp/u25_world_writable_before.txt"
TMP_AFTER="/tmp/u25_world_writable_after.txt"

# 1. 실제 조치 프로세스 시작

# Step 1) world writable 파일 확인
find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_BEFORE"

if [ ! -s "$TMP_BEFORE" ]; then
    # 조치 대상 없음
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="world writable 파일이 존재하지 않아 해당 항목에 대한 보안 위협이 없습니다."
    EVIDENCE="world writable 파일이 존재하지 않아 해당 항목에 대한 보안 위협이 없습니다."
else
    # Step 2) 일반 사용자 쓰기 권한 제거
    while read -r line; do
        FILE_PATH=$(echo "$line" | awk '{print $NF}')
        chmod o-w "$FILE_PATH" 2>/dev/null

        if [ $? -eq 0 ]; then
            ACTION_LOG+="$FILE_PATH 의 권한 제거가 완료되었습니다. "
        else
            ACTION_LOG+="$FILE_PATH 의 권한 제거가 실패하였습니다. "
        fi
    done < "$TMP_BEFORE"

    # Step 3) 조치 후 재확인
    find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_AFTER"

    if [ ! -s "$TMP_AFTER" ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        EVIDENCE="모든 world writable 파일의 일반 사용자 쓰기 권한 제거가 완료되었습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        EVIDENCE="일부 world writable 파일이 여전히 존재하여 취약합니다. 수동 확인이 필요합니다."
        GUIDE="world writable 파일 존재 여부를 확인하고 불필요한 경우 제거해주세요."
    fi
fi

# 3. JSON 표준 출력
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

# 3. 임시 파일 정리
rm -f "$TMP_BEFORE" "$TMP_AFTER"