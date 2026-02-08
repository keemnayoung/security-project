#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-22"
TARGET_FILE="/etc/services"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

# 1. 조치 로직
if [ ! -f "$TARGET_FILE" ]; then
    ACTION_RESULT="FAIL"
    ACTION_LOG="/etc/services 파일이 존재하지 않아 조치 불가"
else
    # 조치 전 소유자/권한 기록
    FILE_OWNER_BEFORE=$(stat -c %U "$TARGET_FILE")
    FILE_PERM_BEFORE=$(stat -c %a "$TARGET_FILE")
    BEFORE_SETTING="소유자: $FILE_OWNER_BEFORE, 권한: $FILE_PERM_BEFORE"

    # 소유자 변경
    chown root "$TARGET_FILE" 2>/dev/null
    # 권한 변경
    chmod 644 "$TARGET_FILE" 2>/dev/null

    # 조치 후 소유자/권한 기록
    FILE_OWNER_AFTER=$(stat -c %U "$TARGET_FILE")
    FILE_PERM_AFTER=$(stat -c %a "$TARGET_FILE")
    AFTER_SETTING="소유자: $FILE_OWNER_AFTER, 권한: $FILE_PERM_AFTER"

    # 조치 결과 확인
    if [ "$FILE_OWNER_AFTER" != "root" ] || [ "$FILE_PERM_AFTER" -gt 644 ]; then
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치 실패: 변경 후 설정 소유자($FILE_OWNER_AFTER), 권한($FILE_PERM_AFTER)"
    else
        ACTION_LOG="조치 완료: 소유자 및 권한이 정상적으로 변경됨"
    fi
fi

# 2. JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF