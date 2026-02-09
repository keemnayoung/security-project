# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : DBMS 계정 비밀번호에 대해 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
# [점검] D-03 비밀번호 사용기간 및 복잡도 정책 적용 여부 (인증 방식 기반 안내)

ITEM_ID="D-03"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정"
DESCRIPTION="pg_hba.conf 인증 방식에 따라 비밀번호 정책 적용 위치 및 확인 항목 안내"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="취약"
RESULT_MSG=""

PG_HBA="/var/lib/pgsql/data/pg_hba.conf"

# pg_hba.conf에서 인증 방식 추출 (주석/공백 제외)
AUTH_METHODS=$(grep -Ev '^\s*#|^\s*$' "$PG_HBA" 2>/dev/null | awk '{print $NF}' | sort -u)

# DB 내부 인증
if echo "$AUTH_METHODS" | grep -Eq 'password|md5|scram-sha-256'; then
  RESULT_MSG="DB 내부 인증(password/md5/scram-sha-256) 사용 중. \
PostgreSQL은 비밀번호 사용기간 및 복잡도 정책을 기본 제공하지 않으므로, \
DB 차원의 비밀번호 정책 확장 사용 여부 또는 \
중앙 인증/OS 인증 전환 여부를 확인해야 함."

# PAM 인증
elif echo "$AUTH_METHODS" | grep -Eq '^pam$'; then
  RESULT_MSG="PAM 인증 사용 중. \
OS 계정 비밀번호 정책이 기관 정책에 맞게 설정되어 있는지 확인 필요. \
확인 항목: /etc/security/pwquality.conf (복잡도), \
/etc/login.defs (PASS_MAX_DAYS 등 사용기간)."

# LDAP / AD 인증
elif echo "$AUTH_METHODS" | grep -Eq 'ldap|gss|sspi'; then
  RESULT_MSG="중앙 인증(LDAP/AD) 연계 사용 중. \
비밀번호 복잡도 및 사용기간 정책은 중앙 인증 시스템에서 관리됨. \
중앙 인증 서버의 비밀번호 정책이 기관 정책에 부합하는지 확인 필요."

# 혼합 또는 식별 불가
else
  RESULT_MSG="pg_hba.conf에서 인증 방식이 혼합되어 있거나 식별 불가. \
각 인증 방식별로 비밀번호 정책 적용 위치(DB/OS/중앙 인증)를 구분하여 \
운영 정책 및 설정을 수동으로 확인해야 함."
fi

cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "importance": "$IMPORTANCE",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": true
}
EOF


