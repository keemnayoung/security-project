#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 사용자 계정과 홈 디렉토리의 일치 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-32"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈 디렉토리로 지정한 디렉토리의 존재 관리"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

RESULT="PASS"
EVIDENCE="홈 디렉토리가 존재하지 않는 계정이 발견되지 않음"

MISSING_HOME_USERS=()


# 2. 진단 로직
while IFS=: read -r username _ uid _ _ homedir shell; do
    # 시스템 계정 제외 (UID 1000 미만)
    if [ "$uid" -ge 1000 ]; then
        if [ ! -d "$homedir" ]; then
            MISSING_HOME_USERS+=("$username:$homedir")
        fi
    fi
done < "$TARGET_FILE"

if [ "${#MISSING_HOME_USERS[@]}" -ne 0 ]; then
    RESULT="FAIL"
    EVIDENCE="홈 디렉토리가 존재하지 않는 계정 발견: ${MISSING_HOME_USERS[*]}"
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$RESULT",
  "evidence": "$EVIDENCE",
  "target_file": "$TARGET_FILE",
  "file_hash": "$(sha256sum $TARGET_FILE | awk '{print $1}')",
  "check_date": "$CHECK_DATE"
}
EOF