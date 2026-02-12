#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-18"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/shadow 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/shadow"
# 2. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    # 1) 조치 전 상태 확인
    BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE")

    EVIDENCE="조치 전 상태: owner=$BEFORE_OWNER, perm=$BEFORE_PERM"

    # 이미 양호한 경우
    if [ "$BEFORE_OWNER" = "root" ] && [ "$BEFORE_PERM" -le 400 ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="취약한 설정이 없습니다. 소유자 및 권한이 이미 안전한 상태였습니다."
        
        GUIDE="KISA 가이드라인에 따른 보안 설정이 완료되었습니다."
    else
        # 2) 조치 수행
        chown root "$TARGET_FILE" 2>/dev/null
        chmod 400 "$TARGET_FILE" 2>/dev/null

        # 3) 조치 후 검증
        AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE")
        AFTER_PERM=$(stat -c "%a" "$TARGET_FILE")

        if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_PERM" -le 400 ]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="/etc/shadow 파일 소유자 및 권한이 기준에 맞게 조치가 완료되었습니다. "
            EVIDENCE+="→ 조치 후 상태: owner=$AFTER_OWNER, perm=$AFTER_PERM"
            GUIDE="KISA 가이드라인에 따른 보안 설정이 완료되었습니다."
        else
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="조치 수행 후에도 설정이 기준을 만족하지 못하고 있습니다. 수동으로 확인해주시기 바랍니다."
            EVIDENCE+="→ 조치 후 상태:  owner=$AFTER_OWNER, perm=$AFTER_PERM 로 여전히 취약합니다."
            GUIDE="/etc/shadow 파일 소유자를 root로 변경하고 권한도 400 이하로 변경하십시오."
        fi
    fi
else
    # 파일 자체가 없는 경우
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="조치 대상 파일(/etc/shadow)이 존재하지 않습니다."
    EVIDENCE="조치 대상 파일(/etc/shadow)이 존재하지 않습니다."
    GUIDE="/etc/shadow 파일 소유자를 root로 변경하고 권한도 400 이하로 변경하십시오."
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