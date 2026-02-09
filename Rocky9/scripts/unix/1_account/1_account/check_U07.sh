#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-07
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 불필요한 계정 제거
# @Description : 시스템에 기본적으로 생성되어 있으나 사용하지 않는 계정(lp, uucp 등)의 존재 여부 점검
# @Criteria_Good : 불필요한 계정이 삭제되거나 잠금 설정된 경우
# @Criteria_Bad : 불필요한 계정이 활성화되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-07"
CATEGORY="계정관리"
TITLE="불필요한 계정 제거"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

# KISA 가이드 및 현업 표준 불필요 계정 목록
DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

STATUS="PASS"
EVIDENCE="불필요한 계정이 존재하지 않습니다."

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 무결성을 위한 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. 불필요 계정 존재 여부 전수 조사
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE"; then
            FOUND_ACCOUNTS+=("$acc")
        fi
    done

    # 3. 결과 판별
    if [ ${#FOUND_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="불필요한 기본 계정 존재 (${FOUND_ACCOUNTS[*]})"
    fi
else
    STATUS="FAIL"
    EVIDENCE="$TARGET_FILE 파일을 찾을 수 없습니다."
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
    "guide": "/etc/passwd에서 lp, uucp 등 사용하지 않는 계정을 userdel로 삭제하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF