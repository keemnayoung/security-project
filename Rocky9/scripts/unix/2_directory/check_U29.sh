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
# ===============================================  =============================

# 1. 항목 정보 정의
ID="U-29"
CATEGORY="파일 및 디렉토리 관리"
TITLE="hosts.lpd 파일 소유자 및 권한 설정"
IMPORTANCE="하"
STATUS="PASS"
EVIDENCE=""
GUIDE="/etc/hosts.lpd 파일을 제거하거나, /etc/hosts.lpd 파일 소유자를 root로 변경하고 권한을 600 이하로 변경해주세요."
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 해당 파일을 실제로 사용하는 레거시 출력 서비스가 있을 경우 인쇄 기능이 제한되거나 동작하지 않을 수 있습니다."
TARGET_FILE="/etc/hosts.lpd"
FILE_HASH="N/A"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")


# 2. 점검 로직
if [ ! -e "$TARGET_FILE" ]; then
    STATUS="PASS"
    EVIDENCE="/etc/hosts.lpd 파일이 존재하지 않습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
        STATUS="PASS"
        EVIDENCE="/etc/hosts.lpd 파일의 소유자 및 권한이 적절하게 설정되어 있어 보안 위협이 없습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="/etc/hosts.lpd 파일의 소유자 또는 권한이 부적절하게 설정되어 있어 재설정이 필요합니다. (owner=$OWNER, perm=$PERM)"
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
    "evidence": "$(echo -e "$EVIDENCE" | sed 's/"/\\"/g')",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF