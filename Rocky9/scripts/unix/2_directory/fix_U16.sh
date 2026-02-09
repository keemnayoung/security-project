#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일의 소유자를 root로 설정하고 권한을 644 이하로 변경
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-16"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/passwd 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="FAIL"
EVIDENCE="N/A"

# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    # 1-1. 조치 전 상태 수집
    BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE")
    EVIDENCE="조치 전 설정: owner=$BEFORE_OWNER, perm=$BEFORE_PERM"

    # 1-2. 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    MODIFIED=0

    # 1-3. 소유자 조치
    if [ "$BEFORE_OWNER" != "root" ]; then
        chown root:root "$TARGET_FILE"
        MODIFIED=1
    fi

    # 1-4. 권한 조치
    if [ "$BEFORE_PERM" -gt 644 ]; then
        chmod 644 "$TARGET_FILE"
        MODIFIED=1
    fi

    # 1-5. 조치 후 상태 검증
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE")
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE")

    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_PERM" -le 644 ]; then
        STATUS="PASS"

        if [ "$MODIFIED" -eq 1 ]; then
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="조치 완료. /etc/passwd 소유자 및 권한 기준 충족 확인 완료."
        else
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="조치 대상 없음. 이미 기준을 충족함."
        fi

        EVIDENCE="$EVIDENCE → 조치 후 설정: owner=$AFTER_OWNER, perm=$AFTER_PERM"

    else
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        ACTION_LOG="조치를 수행했으나 기준을 완전히 충족하지 못함. 수동 확인 필요."
        EVIDENCE="$EVIDENCE → 조치 후 설정: owner=$AFTER_OWNER, perm=$AFTER_PERM"
    fi

else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일($TARGET_FILE)이 없습니다."
    EVIDENCE="파일 없음"
fi

# 2. JSON 표준 출력 (U-01과 동일)
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
