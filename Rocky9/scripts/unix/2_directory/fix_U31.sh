#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-31"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
TARGET_FILE="/etc/passwd"
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 2. 조치 로직
while IFS=: read -r USER _ UID _ _ HOME _; do
    # 시스템 계정 제외 (UID 1000 미만)
    [ "$UID" -lt 1000 ] && continue

    # 홈 디렉토리 존재 확인
    [ ! -d "$HOME" ] && continue

    BEFORE_SETTING="$(stat -c '%U %a' "$HOME")"

    # 소유자 변경
    chown "$USER":"$USER" "$HOME" 2>/dev/null

    # 타 사용자 쓰기 권한 제거
    chmod o-w "$HOME" 2>/dev/null

    AFTER_SETTING="$(stat -c '%U %a' "$HOME")"

    ACTION_LOG+="[USER:$USER HOME:$HOME BEFORE:$BEFORE_SETTING AFTER:$AFTER_SETTING] "
done < /etc/passwd


# 3. 마스터 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "${BEFORE_SETTING:-없음}",
  "after_setting": "${AFTER_SETTING:-없음}",
  "action_log": "${ACTION_LOG:-조치 없음}",
  "action_date": "$ACTION_DATE"
}
EOF