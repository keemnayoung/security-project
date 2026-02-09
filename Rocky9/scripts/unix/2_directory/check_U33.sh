#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-33"
CATEGORY="파일 및 디렉토리 관리"
TITLE="숨겨진 파일 및 디렉토리 검색 및 제거"
IMPORTANCE="하"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 정상 서비스나 사용자 환경에서 필요한 숨김 설정 파일이 함께 삭제될 경우 기능 장애가 발생할 수 있습니다."
CHECK_DATE=$(date "+%Y-%m-%d %H:%M:%S")

EVIDENCE=""
STATUS="PASS"
TARGET_FILE="/"

# 2. 진단 로직
# 숨겨진 파일 검색 (2026-02-08, 권순형 수정: 쉼표로 구분 가능하도록 수정)
HIDDEN_FILES=$(find / -type f -name ".*" 2>/dev/null | head -n 50 | paste -sd ', ' -)
HIDDEN_DIRS=$(find / -type d -name ".*" 2>/dev/null | head -n 50 | paste -sd ', ' -)

if [[ -n "$HIDDEN_FILES" || -n "$HIDDEN_DIRS" ]]; then
    STATUS="FAIL"
    EVIDENCE="Hidden_files: $HIDDEN_FILES, Hidden_directories: $HIDDEN_DIRS"
else
    EVIDENCE="No hidden files or directories detected"
fi

# 3. JSON 결과 출력
echo ""

cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo "$EVIDENCE" | sed 's/"/\\"/g')",
    "guide": "ls -al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"  
}
EOF