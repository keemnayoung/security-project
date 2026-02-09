#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-18"
TARGET_FILE="/etc/shadow"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

# 1. 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    ACTION_RESULT="FAIL"
    ACTION_LOG="/etc/shadow 파일이 존재하지 않음"
else
    # 2. 조치 전 설정 수집
    BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE")
    BEFORE_SETTING="owner=$BEFORE_OWNER, perm=$BEFORE_PERM"

    # 3. 조치 수행
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 400 "$TARGET_FILE" 2>/dev/null

    if [ $? -ne 0 ]; then
        ACTION_RESULT="FAIL"
        ACTION_LOG="소유자 또는 권한 변경 중 오류 발생"
    else
        # 4. 조치 후 설정 수집
        AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE")
        AFTER_PERM=$(stat -c "%a" "$TARGET_FILE")
        AFTER_SETTING="owner=$AFTER_OWNER, perm=$AFTER_PERM"
        ACTION_LOG="/etc/shadow 파일 소유자 및 권한을 root:400으로 설정함"
    fi
fi

# 5. 표준 JSON 출력
echo ""
cat << EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF