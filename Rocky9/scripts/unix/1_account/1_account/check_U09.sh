#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-09
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 계정이 존재하지 않는 GID 금지
# @Description : /etc/group 파일에 설정된 그룹 중 소속된 계정이 없는 불필요한 그룹 점검
# @Criteria_Good : 소속 계정이 없는 불필요한 그룹이 존재하지 않는 경우
# @Criteria_Bad : 소속 계정이 없는 불필요한 그룹이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-09"
CATEGORY="계정관리"
TITLE="계정이 존재하지 않는 GID 금지"
IMPORTANCE="하"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"
UNUSED_GROUPS=()

if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ]; then
    # 1. 파일 해시 추출
    FILE_HASH=$(sha256sum "$GROUP_FILE" | awk '{print $1}')
    
    # 2. 일반 사용자 GID 시작점 설정 (1000 이상)
    GID_MIN=1000 
    
    # 3. 그룹 전수 조사
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            # 해당 GID를 기본 그룹으로 쓰는 유저 확인
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            
            # 유저도 없고 멤버 리스트도 비어있는 경우
            if [[ -z "$USER_EXISTS" && -z "$GMEM" ]]; then
                UNUSED_GROUPS+=("$GNAME($GID)")
            fi
        fi
    done < "$GROUP_FILE"

    # 4. 결과 판별
    if [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="계정이 존재하지 않는 그룹 발견 (${UNUSED_GROUPS[*]})"
    else
        STATUS="PASS"
        EVIDENCE="모든 일반 그룹에 소속된 계정이 존재합니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="필수 설정 파일이 누락되었습니다."
    FILE_HASH="NOT_FOUND"
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
    "guide": "/etc/group 파일에서 소속된 계정이 없는 불필요한 그룹(GID 1000 이상)을 groupdel 명령어로 삭제하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF