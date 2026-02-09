#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-05
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : UID가 0인 일반 계정 존재
# @Description : root 계정 이외에 UID가 0인 계정이 존재하는지 점검
# @Criteria_Good : root 계정 이외에 UID가 0인 계정이 존재하지 않는 경우
# @Criteria_Bad : root 계정 이외에 UID가 0인 계정이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-05"
CATEGORY="계정관리"
TITLE="UID가 0인 일반 계정 존재"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="해당 계정에 반드시 관리자(root) 권한이 필요한 특수 목적이 없다면, UID를 변경하더라도 일반적인 시스템 운영에는 영향이 없습니다. 다만, 조치 후 해당 계정은 더 이상 관리자 권한을 행사할 수 없으므로 기존에 수행하던 작업의 권한 문제를 사전에 검토해야 합니다."

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # root 계정 외에 UID가 0인 계정 리스트 추출
    UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
    
    if [ -z "$UID_ZERO_ACCOUNTS" ]; then
        STATUS="PASS"
        EVIDENCE="root 계정 외에 UID가 0인 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        EVIDENCE="UID가 0인 위험 계정이 존재합니다. ($UID_ZERO_ACCOUNTS)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="설정 파일($TARGET_FILE)을 찾을 수 없습니다."
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "root 이외의 계정 중 UID가 0인 계정의 UID를 1000 이상의 번호로 변경하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "${FILE_HASH:-N/A}",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF