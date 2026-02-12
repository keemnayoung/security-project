#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-31"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈디렉토리 소유자 및 권한 설정"
IMPORTANCE="중"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')


TARGET_FILE="/etc/passwd"
# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    while IFS=: read -r USER _ USER_UID _ _ HOME _; do

        # UID 1000 이상 사용자만 대상
        UID_CLEAN=$(echo "$USER_UID" | tr -cd '0-9')
        [[ -z "$UID_CLEAN" ]] && continue
        (( UID_CLEAN < 1000 )) && continue

        # 홈 디렉터리 존재 시만 처리
        [[ ! -d "$HOME" ]] && continue

        # 현재 상태 확인
        CUR_OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
        CUR_PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')
        OTHER_WRITE=$((CUR_PERM % 10))

        # 조치 수행
        if [[ "$CUR_OWNER" != "$USER" ]]; then
            chown "$USER" "$HOME" 2>/dev/null
        fi

        if (( OTHER_WRITE >= 2 )); then
            chmod o-w "$HOME" 2>/dev/null
        fi

        # 조치 후 재검증
        NEW_OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
        NEW_PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')
        NEW_OTHER_WRITE=$((NEW_PERM % 10))

        if [[ "$NEW_OWNER" != "$USER" || "$NEW_OTHER_WRITE" -ge 2 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE+="[USER:$USER HOME:$HOME OWNER:$NEW_OWNER PERM:$NEW_PERM] "
        else
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            EVIDENCE+="[USER:$USER HOME:$HOME 조치완료] "
        fi

    done < "$TARGET_FILE"

    ACTION_LOG="홈 디렉터리 소유자 및 권한 조치 수행 완료"

else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일(/etc/passwd)이 존재하지 않습니다."
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
    "evidence": "${EVIDENCE:-정상}",
    "guide": "KISA 가이드라인에 따른 홈 디렉터리 권한 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$ACTION_DATE"
}
EOF
