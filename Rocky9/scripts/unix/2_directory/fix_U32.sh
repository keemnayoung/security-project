#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 홈 디렉토리가 존재하지 않는 계정이 발견되지 않도록 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 삭제는 수동으로 처리
#######################

ID="U-32"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈 디렉토리로 지정한 디렉토리의 존재 관리"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MISSING_USERS=()


# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then
    while IFS=: read -r username _ uid _ _ homedir _; do
        # 일반 사용자 계정만 점검
        if [ "$uid" -ge 1000 ]; then
            if [ ! -d "$homedir" ]; then
                MISSING_USERS+=("$username:$homedir")

                # 홈 디렉토리 생성
                mkdir -p "$homedir"
                chown "$username:$username" "$homedir"
                chmod 700 "$homedir"

                ACTION_LOG+="계정 [$username] 홈 디렉토리 [$homedir] 생성 완료. "
            fi
        fi
    done < "$TARGET_FILE"

    if [ "${#MISSING_USERS[@]}" -eq 0 ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="조치 대상 계정 없음."
        EVIDENCE="모든 사용자 계정의 홈 디렉토리가 정상적으로 존재함 (양호)"
    else
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="홈 디렉토리가 없던 계정 조치 완료: ${MISSING_USERS[*]}"
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
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
    "guide": "홈 디렉토리가 존재하지 않는 계정에 대해 홈 디렉토리 설정 또는 계정 제거 필요",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF