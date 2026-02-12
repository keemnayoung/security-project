#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-21"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 1. 실제 조치 프로세스
LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
FOUND=0

for FILE in "${LOG_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        FOUND=1
        TARGET_FILE="$TARGET_FILE $FILE"

        # 조치 수행
        chown root "$FILE" 2>/dev/null
        chmod 640 "$FILE" 2>/dev/null

        AFTER_OWNER=$(stat -c %U "$FILE")
        AFTER_PERM=$(stat -c %a "$FILE")

        # 결과 판정
        if [[ "$AFTER_OWNER" =~ ^(root|bin|sys)$ ]] && [ "$AFTER_PERM" -le 640 ]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG+="$FILE 의 소유자($AFTER_OWNER) 및 권한($AFTER_PERM) 설정이 완료되었습니다."
            EVIDENCE="$FILE 의 소유자($AFTER_OWNER) 및 권한($AFTER_PERM) 설정이 완료되었습니다."
            GUIDE="KISA 가이드라인에 따른 syslog 설정 파일 권한 설정이 완료되었습니다."
        else
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="$FILE 의 조치를 수행했지만 소유자($AFTER_OWNER) 및 권한($AFTER_PERM)으로 여전히 취약합니다. 수동 확인이 필요합니다."
            EVIDENCE+="$FILE 의 조치를 수행했지만 소유자($AFTER_OWNER) 및 권한($AFTER_PERM)으로 여전히 취약합니다. 수동 확인이 필요합니다."
            GUIDE="KISA 가이드라인에 따른 syslog 설정 파일 권한 설정이 완료되었습니다."
        fi
    fi
done

if [ "$FOUND" -eq 0 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="syslog 설정 파일이 존재하지 않아 이미 안전한 상태였습니다."
    EVIDENCE="점검 대상 파일이 존재하지 않습니다."
fi

# 3. JSON 표준 출력
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