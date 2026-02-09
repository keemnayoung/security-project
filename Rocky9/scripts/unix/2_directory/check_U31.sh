#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 1. 항목 정보 정의
CHECK_ID="U-31"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈디렉토리 소유자 및 권한 설정"
IMPORTANCE="중"
STATUS="PASS"
EVIDENCE=""

CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 2. 진단 로직
# 로그인 가능한 사용자 대상으로 홈 디렉토리 점검
while IFS=: read -r USER _ UID _ _ HOME _; do
    # 시스템 계정 제외 (UID 1000 미만)
    [ "$UID" -lt 1000 ] && continue

    # 홈 디렉토리 존재 여부 확인
    if [ ! -d "$HOME" ]; then
        continue
    fi

    OWNER=$(stat -c %U "$HOME")
    PERM=$(stat -c %a "$HOME")
    OTHER_WRITE=$((PERM % 10))

    # 소유자 불일치 또는 타 사용자 쓰기 권한 존재 시 취약
    if [ "$OWNER" != "$USER" ] || [ "$OTHER_WRITE" -ge 2 ]; then
        STATUS="FAIL"
        EVIDENCE+="[USER:$USER HOME:$HOME OWNER:$OWNER PERM:$PERM] "
    fi
done < /etc/passwd


# 3. 마스터 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "${EVIDENCE:-정상}",
  "target_file": "/etc/passwd",
  "file_hash": "$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')",
  "check_date": "$CHECK_DATE"
}
EOF