#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

CHECK_ID="U-19"
TARGET_FILE="/etc/hosts"
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

ACTION_RESULT="FAIL"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

# ----------------------------------------------------------------------------
# 2. 조치 전 설정 값 수집
# ----------------------------------------------------------------------------
if [ -f "$TARGET_FILE" ]; then
    BEFORE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    BEFORE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)
    BEFORE_SETTING="소유자: $BEFORE_OWNER, 권한: $BEFORE_PERM"
else
    BEFORE_SETTING="/etc/hosts 파일이 존재하지 않음"
    ACTION_LOG="조치 실패: 대상 파일이 존재하지 않음"
fi

# ----------------------------------------------------------------------------
# 3. 조치 수행
# ----------------------------------------------------------------------------
if [ -f "$TARGET_FILE" ]; then
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 644 "$TARGET_FILE" 2>/dev/null

    AFTER_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)
    AFTER_SETTING="소유자: $AFTER_OWNER, 권한: $AFTER_PERM"

    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_PERM" -eq 644 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="조치 완료: /etc/hosts 소유자 root, 권한 644 설정"
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치 실패: 설정 적용 확인 실패"
    fi
fi

# 4. 결과 출력 (JSON)
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
