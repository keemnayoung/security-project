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

# 1. 항목 정보 정의
ID="U-10"
CATEGORY="계정관리"
TITLE="동일한 UID 금지"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
DUPLICATE_INFO=""

if [ -f "$TARGET_FILE" ]; then
    # 중복된 UID 값 추출
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort -n | uniq -d)

    if [ -z "$DUPS" ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="모든 사용자가 고유한 식별 번호(UID)를 할당받아 사용 중이며 계정 간 권한 충돌 위험이 없습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        
        # 중복 UID별 계정 매칭 상세화
        for uid in $DUPS; do
            ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
            DUPLICATE_INFO+="UID ${uid}번(${ACCOUNTS}); "
        done
        
        EVIDENCE="동일한 식별 번호를 공유하는 계정(${DUPLICATE_INFO%; })이 식별되어 권한 분리가 필요합니다."
        GUIDE="1. 중복된 계정 중 UID를 변경할 대상을 결정하세요. 2. 해당 사용자가 소유한 파일 리스트를 'find / -uid <UID>'로 먼저 확보하세요. 3. 'usermod -u <새UID> <계정명>'으로 UID를 수정한 뒤, 확보한 파일들의 소유권을 'chown'으로 재설정하십시오."
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="사용자 정보 설정 파일($TARGET_FILE)이 존재하지 않아 계정 식별자 점검이 불가능합니다."
    GUIDE="시스템 환경에 맞는 계정 설정 파일 존재 여부를 수동으로 점검하십시오."
fi

# 3. 마스터 템플릿 표준 출력
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
    "target_file": "$TARGET_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF