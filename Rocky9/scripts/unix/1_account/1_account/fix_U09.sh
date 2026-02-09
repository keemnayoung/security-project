#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-09
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 계정이 존재하지 않는 GID 금지
# @Description : 소속된 계정이 없는 불필요한 그룹을 제거하여 그룹 관리 체계 정비
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-09"
CATEGORY="계정관리"
TITLE="계정이 존재하지 않는 GID 금지"
IMPORTANCE="하"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"

if [ -f "$GROUP_FILE" ]; then
    # 1. 백업 생성
    cp -p "$GROUP_FILE" "${GROUP_FILE}_bak_$TIMESTAMP"

    # 2. 삭제 대상 식별 및 처리
    GID_MIN=1000
    REMOVED_GROUPS=()
    
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            if [[ -z "$USER_EXISTS" && -z "$GMEM" ]]; then
                if groupdel "$GNAME" >/dev/null 2>&1; then
                    REMOVED_GROUPS+=("$GNAME")
                fi
            fi
        fi
    done < "$GROUP_FILE"

    # 3. 검증
    STILL_EXISTS=0
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            [[ -z "$USER_EXISTS" && -z "$GMEM" ]] && ((STILL_EXISTS++))
        fi
    done < "$GROUP_FILE"

    if [ "$STILL_EXISTS" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        if [ ${#REMOVED_GROUPS[@]} -gt 0 ]; then
            ACTION_LOG="조치 완료. 불필요한 그룹(${REMOVED_GROUPS[*]}) 삭제 완료."
        else
            ACTION_LOG="조치 실패. 삭제할 대상 그룹이 없습니다."
        fi
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        ACTION_LOG="주의: 일부 그룹 삭제에 실패했습니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($GROUP_FILE)이 없습니다."
fi

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