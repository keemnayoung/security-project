#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 1. 항목 정보 정의
ID="U-15"
CATEGORY="파일 및 디렉토리 관리"
TITLE="파일 및 디렉터리 소유자 설정"
IMPORTANCE="상"
TARGET_FILE="/"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 해당 파일을 참조하던 서비스나 스크립트가 동작하지 않거나 예기치 않게 중단될 수 있습니다."

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
FILE_HASH="N/A"

# 소유자 또는 그룹이 존재하지 않는 파일/디렉터리 검색
ORPHAN_FILES_RAW=$(find / \
    -xdev \
    \( -nouser -o -nogroup \) \
    2>/dev/null)

if [ -n "$ORPHAN_FILES_RAW" ]; then
    STATUS="FAIL"

    ORPHAN_FILES=$(echo "$ORPHAN_FILES_RAW" | paste -sd ", " -)
    EVIDENCE="소유자 또는 그룹이 존재하지 않는 파일/디렉터리 발견: $ORPHAN_FILES"
else
    EVIDENCE="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리 미존재"
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
    "guide": "소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자를 변경하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
