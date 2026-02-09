#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-17"
TARGET_FILE="system startup scripts"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
BEFORE_SETTING="N/A"
AFTER_SETTING="N/A"

MODIFIED=0
BEFORE_DETAIL=""
AFTER_DETAIL=""

# 1. 조치 대상 파일 수집
if [ -d /etc/rc.d ]; then
    INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null | sed 's/$/*/')
fi

if [ -d /etc/systemd/system ]; then
    SYSTEMD_FILES=$(readlink -f /etc/systemd/system/* 2>/dev/null | sed 's/$/*/')
fi

ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sort -u)


# 2. 조치 수행
if [ -z "$ALL_FILES" ]; then
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치 대상 시스템 시작 스크립트 파일이 존재하지 않음"
else
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        BEFORE_OWNER=$(stat -c "%U" "$FILE")
        BEFORE_PERM=$(stat -c "%A" "$FILE")

        BEFORE_DETAIL+="[$FILE] owner=$BEFORE_OWNER, perm=$BEFORE_PERM\n"

        # 소유자 조치
        if [ "$BEFORE_OWNER" != "root" ]; then
            chown root:root "$FILE"
            MODIFIED=1
        fi

        # 일반 사용자 쓰기 권한 제거
        if [ "$(echo "$BEFORE_PERM" | cut -c9)" = "w" ]; then
            chmod o-w "$FILE"
            MODIFIED=1
        fi

        AFTER_OWNER=$(stat -c "%U" "$FILE")
        AFTER_PERM=$(stat -c "%A" "$FILE")

        AFTER_DETAIL+="[$FILE] owner=$AFTER_OWNER, perm=$AFTER_PERM\n"
    done

    BEFORE_SETTING=$(echo -e "$BEFORE_DETAIL" | sed 's/"/\\"/g')
    AFTER_SETTING=$(echo -e "$AFTER_DETAIL" | sed 's/"/\\"/g')

    # 3. 결과 판단
    FAIL_FLAG=0
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        OWNER=$(stat -c "%U" "$FILE")
        PERM=$(stat -c "%A" "$FILE")

        if [ "$OWNER" != "root" ] || [ "$(echo "$PERM" | cut -c9)" = "w" ]; then
            FAIL_FLAG=1
            break
        fi
    done

    if [ "$FAIL_FLAG" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        if [ "$MODIFIED" -eq 1 ]; then
            ACTION_LOG="시스템 시작 스크립트 파일 소유자 및 권한 조치 완료"
        else
            ACTION_LOG="조치 대상 없음 (이미 기준에 부합)"
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치 수행 후에도 일부 파일이 기준에 부합하지 않음"
    fi
fi

# 4. JSON 출력
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
