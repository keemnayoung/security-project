#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-10
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 동일한 UID 금지
# @Description : /etc/passwd 파일 내 중복된 UID가 존재하는지 점검
# @Criteria_Good : 모든 계정의 UID가 고유하게 설정된 경우
# @Criteria_Bad : 하나 이상의 계정이 동일한 UID를 공유하고 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-10"
CATEGORY="계정관리"
TITLE="동일한 UID 금지"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"
DUPLICATE_INFO=""

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. 중복된 UID 값 추출
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | n | uniq -d)

    if [ -z "$DUPS" ]; then
        STATUS="PASS"
        EVIDENCE="중복된 UID를 사용하는 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        # 3. 중복 UID별 계정 매칭 상세화
        for uid in $DUPS; do
            ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
            DUPLICATE_INFO+="UID $uid($ACCOUNTS); "
        done
        EVIDENCE="동일한 UID 발견 [${DUPLICATE_INFO%; }]"
    fi
else
    STATUS="FAIL"
    EVIDENCE="설정 파일($TARGET_FILE)을 찾을 수 없습니다."
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
    "guide": "/etc/passwd 파일을 확인하여 중복된 UID를 가진 계정의 UID를 수정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF