#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
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

    # 줄바꿈 제거 후 JSON-friendly 문자열로 변환
    ORPHAN_FILES=$(echo "$ORPHAN_FILES_RAW" | tr '\n' ',' | sed 's/,$//')

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
  "target_file": "$TARGET_FILE",
  "file_hash": "$FILE_HASH",
  "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
