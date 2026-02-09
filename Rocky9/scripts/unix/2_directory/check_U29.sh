#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-29"
CATEGORY="파일 및 디렉토리 관리"
TITLE="hosts.lpd 파일 소유자 및 권한 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/hosts.lpd"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 해당 파일을 실제로 사용하는 레거시 출력 서비스가 있을 경우 인쇄 기능이 제한되거나 동작하지 않을 수 있습니다."
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

STATUS="PASS"
EVIDENCE=""

# 2. 점검 로직
if [ ! -e "$TARGET_FILE" ]; then
    STATUS="PASS"
    EVIDENCE="/etc/hosts.lpd 파일이 존재하지 않음"
else
    OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
        STATUS="PASS"
        EVIDENCE="/etc/hosts.lpd 파일 존재하나 소유자(root) 및 권한(${PERM}) 적절"
    else
        STATUS="FAIL"
        EVIDENCE="/etc/hosts.lpd 파일 존재, 소유자=${OWNER}, 권한=${PERM}"
    fi
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
    "check_id": "${CHECK_ID}",
    "category": "${CATEGORY}",
    "title": "${TITLE}",
    "importance": "${IMPORTANCE}",
    "status": "${STATUS}",
    "evidence": "${EVIDENCE}",
    "guide": "/etc/hosts.lpd 파일을 제거하거나, /etc/hosts.lpd 파일 소유자를 root로 변경하고 권한을 600 이하로 변경해주세요.",
    "target_file": "${TARGET_FILE}",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "${CHECK_DATE}"
}
EOF