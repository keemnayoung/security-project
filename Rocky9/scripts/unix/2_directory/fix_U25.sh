#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : world writable 권한 제거 (chmod o-w)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

###################
# 검토 필요
###################

# 1. 기본 변수 정의
CHECK_ID="U-25"
TARGET_FILE="/"
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""
ACTION_RESULT="PASS"

TMP_BEFORE="/tmp/u25_before.txt"
TMP_AFTER="/tmp/u25_after.txt"

# 2. 조치 전 상태 수집
find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_BEFORE"

if [ ! -s "$TMP_BEFORE" ]; then
    BEFORE_SETTING="world writable 파일 없음"
    AFTER_SETTING="조치 불필요"
    ACTION_LOG="조치 대상 파일이 존재하지 않음"
    ACTION_RESULT="PASS"
else
    BEFORE_SETTING=$(cat "$TMP_BEFORE" | tr '\n' '; ')

    # 3. 조치 수행 (o-w 제거)
    while read -r line; do
        FILE_PATH=$(echo "$line" | awk '{print $NF}')
        chmod o-w "$FILE_PATH" 2>/dev/null

        if [ $? -eq 0 ]; then
            ACTION_LOG+="[권한 제거] $FILE_PATH ; "
        else
            ACTION_LOG+="[실패] $FILE_PATH ; "
            ACTION_RESULT="FAIL"
        fi
    done < "$TMP_BEFORE"

    # 4. 조치 후 상태 수집
    find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_AFTER"

    if [ ! -s "$TMP_AFTER" ]; then
        AFTER_SETTING="world writable 파일 제거 완료"
    else
        AFTER_SETTING=$(cat "$TMP_AFTER" | tr '\n' '; ')
        ACTION_RESULT="FAIL"
    fi
fi

# 5. 마스터 JSON 출력
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

# 6. 임시 파일 정리
rm -f "$TMP_BEFORE" "$TMP_AFTER"