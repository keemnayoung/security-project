#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-29"
CATEGORY="파일 및 디렉토리 관리"
TITLE="hosts.lpd 파일 소유자 및 권한 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/hosts.lpd"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="FAIL"
EVIDENCE="N/A"


# 1. 실제 조치 프로세스
if [ ! -e "$TARGET_FILE" ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="/etc/hosts.lpd 파일이 존재하지 않아 조치 불필요"
    EVIDENCE="/etc/hosts.lpd 파일 미존재 (양호)"
else

    chown root "$TARGET_FILE" 2>/dev/null
    chmod 600 "$TARGET_FILE" 2>/dev/null

    OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="/etc/hosts.lpd 파일 소유자 및 권한 설정 완료"
        EVIDENCE="소유자: $OWNER, 권한: $PERM (양호)"
    else
        ACTION_RESULT="FAIL"
        STATUS="FAIL"
        ACTION_LOG="/etc/hosts.lpd 파일 권한 또는 소유자 설정 실패"
        EVIDENCE="소유자: $OWNER, 권한: $PERM (취약)"
    fi
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