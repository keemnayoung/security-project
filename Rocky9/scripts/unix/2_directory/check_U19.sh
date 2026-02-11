#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-19"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/hosts 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="/etc/hosts 파일의 소유자와 권한을 root(644)로 조치하면 일반 사용자의 임의 수정이 차단되어 보안은 강화되지만, 기존에 비root 계정이 해당 파일을 직접 수정해 사용하던 환경에서는 호스트 해석 변경 작업이 불가능해져 운영·개발 편의성이 일부 저하될 수 있습니다."
GUIDE="/etc/hosts 파일 소유자를 root로 변경하고 권한도 644 이하로 변경하십시오."
TARGET_FILE="/etc/hosts"
FILE_HASH="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 2. 진단 로직
if [ -f "$TARGET_FILE" ]; then
    FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$FILE_OWNER" = "root" ] && [ "$FILE_PERM" -le 644 ]; then
        STATUS="PASS"
        EVIDENCE="/etc/hosts 파일 소유자(root) 및 권한(644 이하) 설정이 적절하여 이 항목에 대한 보안 위협이 없습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="/etc/hosts 파일 설정이 부적절합니다. /etc/hosts 파일의 소유자 또는 권한 재설정이 필요합니다. (owner=$FILE_OWNER, perm=$FILE_PERM)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="/etc/hosts 파일이 존재하지 않습니다."
    GUIDE="점검 대상 파일이 없습니다."
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