#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-25
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : world writable 파일 점검
# @Description : 불필요한 world writable 파일 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-25"
CATEGORY="파일 및 디렉토리 관리"
TITLE="world writable 파일 점검"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 world writable 파일 존재 여부를 확인하고 불필요한 경우 제거해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 world writable 권한을 전제로 동작하던 스크립트나 서비스가 있다면 일부 기능 장애가 발생할 수 있습니다."
TARGET_FILE="/"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
TMP_RESULT_FILE="/tmp/U25_world_writable_files.txt"

# world writable 파일 탐색
find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null > "$TMP_RESULT_FILE"

FILE_COUNT=$(wc -l < "$TMP_RESULT_FILE")

if [ "$FILE_COUNT" -eq 0 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="world writable 파일이 존재하지 않아 이 항목에서 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    FILE_LIST=$(paste -sd ", " "$TMP_RESULT_FILE")
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="world writable 파일이 존재하여 보안을 위해 다음 경로에 있는 파일들을 확인 후 불필요한 경우 제거하십시오. "
    EVIDENCE+="($FILE_LIST)"
fi


# 3. 무결성 정보
if command -v sha256sum >/dev/null 2>&1; then
    FILE_HASH=$(sha256sum "$TMP_RESULT_FILE" | awk '{print $1}')
else
    FILE_HASH="N/A"
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF

# 5. 임시 파일 정리
rm -f "$TMP_RESULT_FILE"