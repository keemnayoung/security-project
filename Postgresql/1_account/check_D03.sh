# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : DBMS 계정 비밀번호에 대해 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-03"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정"
DESCRIPTION="Rocky Linux 10.1 환경에서 PAM 인증 사용 여부에 따른 DBMS 계정 비밀번호 정책 적용 여부 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)


pam_auth=$(grep -E "^[^#].*pam" /var/lib/pgsql/data/pg_hba.conf 2>/dev/null)
pwquality=$(grep pam_pwquality /etc/pam.d/system-auth 2>/dev/null)
max_days=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')

if [ -n "$pam_auth" ]; then
  # PAM 인증 사용
  if [ -n "$pwquality" ] && [ "$max_days" -gt 0 ]; then
    STATUS="양호"
    RESULT_MSG="PAM 인증 기반 비밀번호 복잡도 및 사용 기간 정책 적용됨 (자동 확인)"
  else
    STATUS="취약"
    RESULT_MSG="PAM 인증은 사용 중이나 비밀번호 복잡도 또는 사용 기간 정책 미흡"
  fi
else
  # PAM 인증 미사용
  STATUS="취약"
  RESULT_MSG="DB 내부 인증 사용으로 비밀번호 사용 기간 정책을 자동 확인할 수 없음 (운영 절차 또는 외부 인증 정책 수동 확인 필요)"
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

