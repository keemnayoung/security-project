# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정
# @Description : 로그인 실패 시 계정 잠금 정책 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-09"
CATEGORY="계정관리"
CHECK_ITEM="로그인 실패 횟수 제한"
DESCRIPTION="로그인 실패 시 계정 잠금 정책 설정 여부 점검"
SEVERITY="중"
CHECKED_AT=$(date -Iseconds)


pam_pg=$(grep -E "^[^#].*pam" /var/lib/pgsql/data/pg_hba.conf 2>/dev/null)
pam_lock=$(grep -E "pam_faillock|pam_tally2" /etc/pam.d/system-auth 2>/dev/null)

STATUS="취약"
RESULT_MSG="PostgreSQL은 로그인 실패 횟수 제한 기능을 제공하지 않으며, PAM 기반 계정 잠금 정책에 대한 수동 확인 필요"

if [ -n "$pam_pg" ] && [ -n "$pam_lock" ]; then
  RESULT_MSG="PAM 기반 계정 잠금 정책 설정은 확인되었으나 DB 적용 여부는 수동 확인 필요"
fi

cat <<EOF
{ "item_id":"$ITEM_ID",
"category":"$CATEGORY",
"check_item":"$CHECK_ITEM",
"description":"$DESCRIPTION",
"severity":"$SEVERITY",
"checked_at":"$CHECKED_AT",
"status":"$STATUS",
"result":"$RESULT_MSG",
"checked":true }
EOF
