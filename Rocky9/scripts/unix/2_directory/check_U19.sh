#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
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
CHECK_ID="U-19"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/hosts 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/hosts"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="/etc/hosts 파일의 소유자와 권한을 root(644)로 조치하면 일반 사용자의 임의 수정이 차단되어 보안은 강화되지만, 기존에 비root 계정이 해당 파일을 직접 수정해 사용하던 환경에서는 호스트 해석 변경 작업이 불가능해져 운영·개발 편의성이 일부 저하될 수 있습니다."

STATUS="FAIL"
EVIDENCE=""
FILE_HASH="N/A"

# 2. 진단 로직
if [ -f "$TARGET_FILE" ]; then
    FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    if [ "$FILE_OWNER" = "root" ] && [ "$FILE_PERM" -le 644 ]; then
        STATUS="PASS"
        EVIDENCE="소유자: $FILE_OWNER, 권한: $FILE_PERM"
    else
        STATUS="FAIL"
        EVIDENCE="소유자: $FILE_OWNER, 권한: $FILE_PERM (기준: root / 644 이하)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="/etc/hosts 파일이 존재하지 않음"
fi

# 3. 결과 출력 (JSON)
cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "/etc/hosts 파일 소유자를 root로 변경하고 권한도 644 이하로 변경해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF