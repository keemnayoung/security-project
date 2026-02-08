#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

######################
# 수동 점검
######################

# 1. 기본 변수 정의
ID="U-33"
TARGET_FILE="/"
ACTION_DATE=$(date "+%Y-%m-%d %H:%M:%S")

ACTION_RESULT=""
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

# 2. 조치 로직 (수동 확인)
HIDDEN_FILES=$(find / -type f -name ".*" 2>/dev/null | head -n 50)
HIDDEN_DIRS=$(find / -type d -name ".*" 2>/dev/null | head -n 50)

BEFORE_SETTING="Hidden files:\n$HIDDEN_FILES\n\nHidden directories:\n$HIDDEN_DIRS"

if [[ -n "$HIDDEN_FILES" || -n "$HIDDEN_DIRS" ]]; then
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="Hidden files or directories detected. Administrator review and manual removal required using rm / rm -r."
    AFTER_SETTING="No automatic changes applied."
else
    ACTION_RESULT="NO_ACTION_REQUIRED"
    ACTION_LOG="No hidden files or directories detected."
    AFTER_SETTING="System already compliant."
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$(echo -e "$BEFORE_SETTING" | sed 's/"/\\"/g')",
  "after_setting": "$(echo -e "$AFTER_SETTING" | sed 's/"/\\"/g')",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF