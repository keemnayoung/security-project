# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-10"
CATEGORY="접근관리"
CHECK_ITEM="원격 접속 IP 제한"
DESCRIPTION="지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

# IPv4 / IPv6 전체 허용 여부 점검
open_ipv4=$(grep -E "^[^#].*0.0.0.0/0" /var/lib/pgsql/data/pg_hba.conf)
open_ipv6=$(grep -E "^[^#].*::/0" /var/lib/pgsql/data/pg_hba.conf)

if [ -n "$open_ipv4" ] || [ -n "$open_ipv6" ]; then
  STATUS="취약"
  RESULT_MSG="전체 IP(0.0.0.0/0 또는 ::/0) 접근 허용 설정 존재"
else
  STATUS="양호"
  RESULT_MSG="지정된 IP 대역에서만 DB 접속 허용"
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
