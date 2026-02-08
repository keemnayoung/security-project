#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
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
  "target_file": "${TARGET_FILE}",
  "check_date": "${CHECK_DATE}"
}
EOF