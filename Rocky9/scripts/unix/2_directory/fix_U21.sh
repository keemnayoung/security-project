#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

CHECK_ID="U-21"
TARGET_FILE=""
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")


# 1. 조치 로직
for FILE in "${LOG_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        TARGET_FILE="$TARGET_FILE $FILE"

        BEFORE_OWNER=$(stat -c %U "$FILE")
        BEFORE_PERM=$(stat -c %a "$FILE")
        BEFORE_SETTING="$BEFORE_SETTING [$FILE] owner=$BEFORE_OWNER, perm=$BEFORE_PERM;"

        chown root "$FILE" 2>/dev/null
        chmod 640 "$FILE" 2>/dev/null

        AFTER_OWNER=$(stat -c %U "$FILE")
        AFTER_PERM=$(stat -c %a "$FILE")
        AFTER_SETTING="$AFTER_SETTING [$FILE] owner=$AFTER_OWNER, perm=$AFTER_PERM;"

        ACTION_LOG="$ACTION_LOG [$FILE] 소유자 root, 권한 640 설정 완료;"
    fi
done

if [ -z "$TARGET_FILE" ]; then
    ACTION_RESULT="NO_ACTION"
    ACTION_LOG="syslog 설정 파일이 존재하지 않아 조치하지 않음"
fi


# 2. 마스터 JSON 출력
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