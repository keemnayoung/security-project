#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-23"
CATEGORY="파일 및 디렉토리 관리"
TITLE="SUID, SGID, Sticky bit 설정 파일 점검"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 불필요한 SUID, SGID 권한 또는 해당 파일을 제거하십시오. 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거해야 합니다."
ACTION_RESULT="N/A"
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="불필요한 SUID·SGID 권한을 제거할 경우, 해당 파일을 의존하던 일부 서비스나 관리 작업이 정상적으로 수행되지 않을 수 있으므로 조치 전 사용 여부에 대한 검토가 필요합니다."
TARGET_FILE="N/A"
FILE_HASH="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 2. 진단 로직
# SUID 또는 SGID가 설정된 root 소유 파일 검색
RESULT=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

if [ -n "$RESULT" ]; then
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="SUID 또는 SGID가 설정된 불필요한 파일이 발견되어 보안을 위한 수동 조치가 필요합니다. 파일 항목은 다음과 같습니다. ("
    EVIDENCE+=$(echo "$RESULT" | paste -sd ', ' -)
    EVIDENCE+=")"
else
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="SUID 또는 SGID가 설정된 불필요한 파일이 발견되지 않아 이 항목에서 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
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