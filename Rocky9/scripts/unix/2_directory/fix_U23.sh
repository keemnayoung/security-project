#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 주요 실행 파일의 권한에 SUID와 SGID에 대한 설정 해제
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 검토 필요
#######################


# 1. 기본 변수 정의
ID="U-23"
TARGET_FILE="/"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 2. 조치 대상 수집
SUID_SGID_FILES=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

if [ -z "$SUID_SGID_FILES" ]; then
    ACTION_LOG="조치 대상 SUID/SGID 파일이 존재하지 않음"
    BEFORE_SETTING="N/A"
    AFTER_SETTING="N/A"
else
    # 쉼표 구분으로 BEFORE_SETTING 저장
    BEFORE_SETTING=$(echo "$SUID_SGID_FILES" | xargs ls -al 2>/dev/null | tr '\n' ',' | sed 's/,$//')

    # 3. SUID / SGID 제거
    while read -r FILE; do
        chmod -s "$FILE" 2>/dev/null
        if [ $? -eq 0 ]; then
            ACTION_LOG="${ACTION_LOG}SUID/SGID 제거 완료: ${FILE}\n"
        else
            ACTION_LOG="${ACTION_LOG}SUID/SGID 제거 실패: ${FILE}\n"
            ACTION_RESULT="FAIL"
        fi
    done <<< "$SUID_SGID_FILES"

    # 쉼표 구분으로 AFTER_SETTING 저장
    AFTER_SETTING=$(echo "$SUID_SGID_FILES" | xargs ls -al 2>/dev/null | tr '\n' ',' | sed 's/,$//')
fi

# 4. 마스터 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$(echo -e "$ACTION_LOG" | tr '\n' ',' | sed 's/,$//')",
  "action_date": "$ACTION_DATE"
}
EOF
