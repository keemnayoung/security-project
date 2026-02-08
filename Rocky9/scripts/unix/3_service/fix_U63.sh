#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux 9
# @Importance : 중
# @Title : /etc/sudoers 파일 소유자 및 권한 설정
# @Description : /etc/sudoers 파일의 소유자를 root, 권한을 640으로 변경
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-63 /etc/sudoers 파일 소유자 및 권한 설정

# 1. 항목 정보 정의
ID="U-63"
CATEGORY="서비스관리"
TITLE="/etc/sudoers 파일 소유자 및 권한 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/sudoers"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

if [ -f "$TARGET_FILE" ]; then
    # 현재 상태 확인
    OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    BEFORE_SETTING="소유자: $OWNER, 권한: $PERMS"
    
    # 소유자 변경
    if [ "$OWNER" != "root" ]; then
        chown root "$TARGET_FILE"
        ACTION_LOG="$ACTION_LOG 소유자를 root로 변경;"
    fi
    
    # 권한 변경
    if [ "$PERMS" -gt 640 ]; then
        chmod 640 "$TARGET_FILE"
        ACTION_LOG="$ACTION_LOG 권한을 640으로 변경;"
    fi
    
    # 변경 후 상태 확인
    OWNER_AFTER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    PERMS_AFTER=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    AFTER_SETTING="소유자: $OWNER_AFTER, 권한: $PERMS_AFTER"
    
    [ -z "$ACTION_LOG" ] && ACTION_LOG="이미 적절히 설정되어 있음"
else
    ACTION_RESULT="FAIL"
    ACTION_LOG="/etc/sudoers 파일이 존재하지 않음"
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
