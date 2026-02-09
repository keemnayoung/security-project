#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-17"
CATEGORY="파일 및 디렉토리 관리"
TITLE="시스템 시작 스크립트 파일 권한 설정"
IMPORTANCE="상"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="FAIL"
EVIDENCE=""

EVIDENCE_LINES=()
MODIFIED=0
FAIL_FLAG=0


# 1. 조치 대상 수집 (KISA 가이드 기준)
if [ -d /etc/rc.d ]; then
    INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null | sed 's/$/*/')
fi

if [ -d /etc/systemd/system ]; then
    SYSTEMD_FILES=$(readlink -f /etc/systemd/system/* 2>/dev/null | sed 's/$/*/')
fi

ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sort -u)


# 2. 조치 수행
if [ -z "$ALL_FILES" ]; then
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 시스템 시작 스크립트 파일이 존재하지 않음"
    EVIDENCE="조치 대상 파일 없음"
else
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        # 소유자 및 권한 조치
        OWNER=$(stat -c "%U" "$FILE")
        PERM=$(stat -c "%A" "$FILE")

        if [ "$OWNER" != "root" ]; then
            chown root:root "$FILE"
            MODIFIED=1
        fi

        if [ "$(echo "$PERM" | cut -c9)" = "w" ]; then
            chmod o-w "$FILE"
            MODIFIED=1
        fi
    done

    # 3. 조치 후 재검증
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        AFTER_OWNER=$(stat -c "%U" "$FILE")
        AFTER_PERM=$(stat -c "%A" "$FILE")

        if [ "$AFTER_OWNER" = "root" ] && [ "$(echo "$AFTER_PERM" | cut -c9)" != "w" ]; then
            EVIDENCE_LINES+=("[양호] $FILE (owner=root, perm=$AFTER_PERM)")
        else
            EVIDENCE_LINES+=("[취약] $FILE (owner=$AFTER_OWNER, perm=$AFTER_PERM)")
            FAIL_FLAG=1
        fi
    done

    if [ "$FAIL_FLAG" -eq 0 ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        if [ "$MODIFIED" -eq 1 ]; then
            ACTION_LOG="시스템 시작 스크립트 파일 소유자 및 권한 조치 완료"
        else
            ACTION_LOG="조치 대상 없음 (이미 기준에 부합)"
        fi
    else
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        ACTION_LOG="일부 시스템 시작 스크립트 파일이 기준에 부합하지 않음"
    fi

    EVIDENCE=$(printf "%s\\n" "${EVIDENCE_LINES[@]}" | sed 's/"/\\"/g')
fi


# 4. JSON 표준 출력 (U-01 기준)
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF