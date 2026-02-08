#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 로그에 대한 접근 통제 및 관리 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-67"
CATEGORY="로그 관리"
TITLE="로그 디렉터리 소유자 및 권한 설정"
IMPORTANCE="중"
TARGET_DIR="/var/log"
STATUS="PASS"
EVIDENCE="모든 로그 파일의 소유자 및 권한이 적절함"
TARGET_FILE="$TARGET_DIR"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

VULN_FILES=()

# 2. 진단 로직
if [ -d "$TARGET_DIR" ]; then
    while IFS= read -r file; do
        OWNER=$(stat -c %U "$file" 2>/dev/null)
        PERM=$(stat -c %a "$file" 2>/dev/null)

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
            STATUS="FAIL"
            VULN_FILES+=("$file (owner=$OWNER, perm=$PERM)")
        fi
    done < <(find "$TARGET_DIR" -type f 2>/dev/null)
else
    STATUS="FAIL"
    EVIDENCE="/var/log 디렉터리가 존재하지 않음"
fi

if [ "$STATUS" = "FAIL" ] && [ ${#VULN_FILES[@]} -gt 0 ]; then
    EVIDENCE=$(printf "%s\n" "${VULN_FILES[@]}")
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
  "evidence": "$(echo "$EVIDENCE" | sed ':a;N;$!ba;s/\n/ | /g')",
  "target_file": "$TARGET_FILE",
  "check_date": "$CHECK_DATE"
}
EOF