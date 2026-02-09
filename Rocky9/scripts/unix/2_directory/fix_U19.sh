#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : RHEL
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-19"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/hosts 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/hosts"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE=""


# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    # 1-1. 조치 전 상태 수집 (Evidence 용)
    BEFORE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    BEFORE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)
    EVIDENCE="조치 전 - 소유자: $BEFORE_OWNER, 권한: $BEFORE_PERM"

    # 1-2. 조치 수행
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 644 "$TARGET_FILE" 2>/dev/null

    # 1-3. 조치 후 검증
    AFTER_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_PERM" -eq 644 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="조치 완료. /etc/hosts 소유자 root 및 권한 644 설정 확인 완료."
        EVIDENCE="$EVIDENCE → 조치 후 - 소유자: $AFTER_OWNER, 권한: $AFTER_PERM (양호)"
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        ACTION_LOG="조치 수행은 되었으나 설정 적용이 기준에 부합하지 않습니다. 수동 확인이 필요합니다."
        EVIDENCE="$EVIDENCE → 조치 후 - 소유자: $AFTER_OWNER, 권한: $AFTER_PERM (취약)"
    fi

else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일($TARGET_FILE)이 존재하지 않습니다."
    EVIDENCE="파일 없음"
fi


# 2. JSON 표준 출력
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