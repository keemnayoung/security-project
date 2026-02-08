#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-23"
CATEGORY="파일 및 디렉토리 관리"
TITLE="SUID, SGID, Sticky bit 설정 파일 점검"
IMPORTANCE="상"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

TARGET_FILE="/"
EVIDENCE=""
STATUS="PASS"


# 2. 진단 로직
# SUID 또는 SGID가 설정된 root 소유 파일 검색
RESULT=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

if [ -n "$RESULT" ]; then
    STATUS="FAIL"
    EVIDENCE=$(echo "$RESULT" | tr '\n' ',' | sed 's/,$//')
else
    EVIDENCE="SUID 또는 SGID가 설정된 불필요한 파일이 발견되지 않음"
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
  "target_file": "$TARGET_FILE",
  "file_hash": "N/A",
  "check_date": "$CHECK_DATE"
}
EOF