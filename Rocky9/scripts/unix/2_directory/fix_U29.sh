#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 기본 변수 정의
ID="U-29"
TARGET_FILE="/etc/hosts.lpd"
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""


# 2. 조치 로직
if [ ! -e "$TARGET_FILE" ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="/etc/hosts.lpd 파일이 존재하지 않아 조치 불필요"
    BEFORE_SETTING="파일 없음"
    AFTER_SETTING="파일 없음"
else
    BEFORE_SETTING=$(ls -l "$TARGET_FILE" 2>/dev/null)

    # 소유자 및 권한 변경
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 600 "$TARGET_FILE" 2>/dev/null

    if [ $? -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="/etc/hosts.lpd 파일 소유자(root) 및 권한(600)으로 설정 완료"
        AFTER_SETTING=$(ls -l "$TARGET_FILE" 2>/dev/null)
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="/etc/hosts.lpd 파일 소유자 또는 권한 변경 실패"
        AFTER_SETTING=$(ls -l "$TARGET_FILE" 2>/dev/null)
    fi
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "${ID}",
  "action_result": "${ACTION_RESULT}",
  "before_setting": "${BEFORE_SETTING}",
  "after_setting": "${AFTER_SETTING}",
  "action_log": "${ACTION_LOG}",
  "action_date": "${ACTION_DATE}"
}
EOF