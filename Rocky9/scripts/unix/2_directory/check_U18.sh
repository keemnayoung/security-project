#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-18"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/shadow 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못 설정될 경우 인증 관련 서비스에서 로그인 오류가 발생할 수 있습니다."
GUIDE="/etc/shadow 파일 소유자를 root로 변경하고 권한도 400 이하로 변경하십시오."
TARGET_FILE="/etc/shadow"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
# 파일 존재 여부 확인
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    EVIDENCE="/etc/shadow 파일이 존재하지 않습니다."
    GUIDE="점검 대상 파일이 없습니다."
else
    FILE_OWNER=$(stat -c "%U" "$TARGET_FILE")
    FILE_PERM=$(stat -c "%a" "$TARGET_FILE")

    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 400 ]; then
        STATUS="FAIL"
        EVIDENCE="/etc/shadow 파일 설정이 부적절합니다. /etc/shadow 파일의 소유자 또는 권한 재설정이 필요합니다. (owner=$FILE_OWNER, perm=$FILE_PERM)"
    else
        EVIDENCE="/etc/shadow 파일 소유자 및 권한 설정이 적절하여 이 항목에 대한 보안 위협이 없습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    fi
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF