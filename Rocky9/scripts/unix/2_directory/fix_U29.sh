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
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 1. 실제 조치 프로세스
TARGET_FILE="/etc/hosts.lpd"

if [ ! -e "$TARGET_FILE" ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    ACTION_LOG="/etc/hosts.lpd 파일이 존재하지 않아 이 항목에 대한 보안 위협이 없습니다."
    EVIDENCE="/etc/hosts.lpd 파일이 존재하지 않아 이 항목에 대한 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else

    chown root "$TARGET_FILE" 2>/dev/null
    chmod 600 "$TARGET_FILE" 2>/dev/null

    OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="/etc/hosts.lpd 파일 소유자($OWNER) 및 권한($PERM) 설정이 완료되었습니다."
        EVIDENCE="/etc/hosts.lpd 파일 소유자($OWNER) 및 권한($PERM) 설정이 완료되었습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        ACTION_RESULT="FAIL"
        STATUS="FAIL"
        ACTION_LOG="/etc/hosts.lpd 파일 소유자($OWNER) 및 권한($PERM) 설정이 실패하였습니다."
        EVIDENCE="/etc/hosts.lpd 파일 소유자($OWNER) 및 권한($PERM) 설정이 실패하였습니다."
        GUIDE="/etc/hosts.lpd 파일을 제거하거나, /etc/hosts.lpd 파일 소유자를 root로 변경하고 권한을 600 이하로 변경해주세요."
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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF