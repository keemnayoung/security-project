#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일의 소유자를 root로 설정하고 권한을 644 이하로 변경
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-16"
TARGET_FILE="/etc/passwd"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
BEFORE_SETTING="N/A"
AFTER_SETTING="N/A"

# 1. 대상 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    ACTION_RESULT="FAIL"
    ACTION_LOG="/etc/passwd 파일이 존재하지 않음"
else
    # 2. 조치 전 설정 수집
    BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE")
    BEFORE_SETTING="owner=$BEFORE_OWNER, perm=$BEFORE_PERM"

    MODIFIED=0

    # 3. 소유자 조치
    if [ "$BEFORE_OWNER" != "root" ]; then
        chown root:root "$TARGET_FILE"
        MODIFIED=1
    fi

    # 4. 권한 조치 (644 초과 시)
    if [ "$BEFORE_PERM" -gt 644 ]; then
        chmod 644 "$TARGET_FILE"
        MODIFIED=1
    fi

    # 5. 조치 후 설정 수집
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE")
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE")
    AFTER_SETTING="owner=$AFTER_OWNER, perm=$AFTER_PERM"

    # 6. 결과 판단
    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_PERM" -le 644 ]; then
        ACTION_RESULT="SUCCESS"
        if [ "$MODIFIED" -eq 1 ]; then
            ACTION_LOG="/etc/passwd 파일 소유자 및 권한 조치 완료"
        else
            ACTION_LOG="조치 대상 없음 (이미 적절한 설정)"
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치 수행 후에도 설정이 기준에 부합하지 않음"
    fi
fi

# 7. JSON 출력
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
