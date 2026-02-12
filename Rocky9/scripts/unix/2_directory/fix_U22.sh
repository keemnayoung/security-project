#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-22"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/services 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/services"

# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    # 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 소유자 및 권한 조치
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 644 "$TARGET_FILE" 2>/dev/null

    # 조치 후 상태 확인
    AFTER_OWNER=$(stat -c %U "$TARGET_FILE")
    AFTER_PERM=$(stat -c %a "$TARGET_FILE")

    if [[ "$AFTER_OWNER" == "root" || "$AFTER_OWNER" == "bin" || "$AFTER_OWNER" == "sys" ]] \
       && [ "$AFTER_PERM" -le 644 ]; then

        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="/etc/services 의 소유자($AFTER_OWNER) 및 권한($AFTER_PERM) 설정이 완료되었습니다."
        EVIDENCE="/etc/services 의 소유자($AFTER_OWNER) 및 권한($AFTER_PERM) 설정이 완료되었습니다."
        GUIDE="KISA 가이드라인에 따른 보안 설정이 완료되었습니다."
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        ACTION_LOG="$FILE 의 조치를 수행했지만 소유자($AFTER_OWNER) 및 권한($AFTER_PERM)으로 여전히 취약합니다. 수동 확인이 필요합니다."
        EVIDENCE="$FILE 의 조치를 수행했지만 소유자($AFTER_OWNER) 및 권한($AFTER_PERM)으로 여전히 취약합니다. 수동 확인이 필요합니다."
        GUIDE="/etc/services 파일 소유자를 root로 변경하고 권한도 644로 변경해주세요."
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일(/etc/services)이 존재하지 않습니다."
    EVIDENCE="조치 대상 파일(/etc/services)이 존재하지 않습니다."
    GUIDE="/etc/services 파일 소유자를 root로 변경하고 권한도 644로 변경해주세요."
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