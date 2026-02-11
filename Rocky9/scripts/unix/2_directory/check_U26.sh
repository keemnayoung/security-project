#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev에 존재하지 않는 device 파일 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-26"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/dev에 존재하지 않는 device 파일 점검"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 /dev 디렉터리에 대한 파일 목록을 점검 후 major, minor number를 가지지 않는 device 파일을 제거해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못된 파일을 삭제할 경우 일부 하드웨어나 서비스가 일시적으로 동작하지 않을 수 있습니다."
TARGET_FILE="/dev/*"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
# /dev 디렉터리 내 일반 파일은 비정상 가능성이 높음
INVALID_FILES=$(find /dev -type f 2>/dev/null)

if [ -n "$INVALID_FILES" ]; then
  STATUS="FAIL"
  ACTION_RESULT="PARTIAL_SUCCESS"

  # 줄바꿈 → 쉼표 구분 문자열로 변환
  INVALID_FILES=$(echo "$INVALID_FILES" | paste -sd ", " -)

  EVIDENCE="불필요하거나 존재하지 않는 device 파일 발견되었습니다. 보안을 위해 다음 파일들을 확인 후 수동 조치해주십시오. ($INVALID_FILES)"
else
  STATUS="PASS"
  ACTION_RESULT="SUCCESS"
  EVIDENCE="불필요하거나 존재하지 않는 device 파일이 발견되지 않음"
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