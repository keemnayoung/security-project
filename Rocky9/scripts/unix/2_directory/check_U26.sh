#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-26"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/dev에 존재하지 않는 device 파일 점검"
IMPORTANCE="상"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못된 파일을 삭제할 경우 일부 하드웨어나 서비스가 일시적으로 동작하지 않을 수 있습니다."
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")
TARGET_DIR="/dev"

STATUS="PASS"
EVIDENCE="불필요하거나 존재하지 않는 device 파일이 발견되지 않음"

# 2. 진단 로직
# /dev 디렉터리 내 일반 파일은 비정상 가능성이 높음
INVALID_FILES=$(find /dev -type f 2>/dev/null)

if [ -n "$INVALID_FILES" ]; then
    STATUS="FAIL"

    # 줄바꿈 → 쉼표 구분 문자열로 변환
    INVALID_FILES_CSV=$(echo "$INVALID_FILES" | paste -sd ", " -)

    EVIDENCE="불필요하거나 존재하지 않는 device 파일 발견: $INVALID_FILES_CSV"
fi

# 3. 마스터 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "major, minor number를 가지지 않는 device 파일을 제거해주세요.",
  "target_file": "$TARGET_DIR",
  "file_hash": "N/A",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",  
  "check_date": "$CHECK_DATE"
}
EOF