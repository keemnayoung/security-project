#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-08
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 그룹(root)에 불필요한 일반 계정이 포함되어 있는지 점검
# @Criteria_Good : 관리자 그룹에 root 계정만 포함되어 있는 경우
# @Criteria_Bad : 관리자 그룹에 root 이외의 일반 계정이 포함되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-08"
CATEGORY="계정관리"
TITLE="관리자 그룹에 최소한의 계정 포함"
IMPORTANCE="중"
TARGET_FILE="/etc/group"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="관리자(root) 그룹에 불필요하게 포함된 일반 계정을 제거하는 조치로, 일반적인 시스템 운영에는 영향이 없습니다. 다만, 조치 후 해당 계정은 root 그룹 권한이 필요한 특정 파일이나 디렉터리에 접근할 수 없게 되므로, 업무상 권한이 필요한 계정인지 사전에 확인이 필요합니다."

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. root 그룹(GID 0)에 속한 사용자 리스트 추출
    ROOT_GROUP_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4)
    
    # root를 제외한 계정 필터링
    EXTRA_USERS=$(echo "$ROOT_GROUP_USERS" | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | xargs | tr ' ' ',')

    if [ -z "$EXTRA_USERS" ]; then
        STATUS="PASS"
        EVIDENCE="관리자 그룹(root)에 필수 계정 외에 다른 사용자가 포함되어 있지 않아 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="관리자 권한을 가진 그룹에 일반 사용자 계정($EXTRA_USERS)이 포함되어 있어, 권한 오남용 방지를 위한 조치가 필요합니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="그룹 정보 설정 파일($TARGET_FILE)이 식별되지 않아 정확한 권한 점검을 위한 시스템 확인 조치가 필요합니다."
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "/etc/group 파일에서 root 그룹에 등록된 불필요한 일반 계정을 제거하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF