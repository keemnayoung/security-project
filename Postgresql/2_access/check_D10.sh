# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-10"
CATEGORY="접근관리"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="/var/lib/pgsql/data/pg_hba.conf"
ACTION_IMPACT="지정되지 않은 IP 주소에서의 DB 접속이 차단되며, DB에 접근하는 애플리케이션 서버의 IP가 허용 목록에 포함되지 않은 경우 서비스 접속 오류가 발생할 수 있으므로 사전 확인이 필요합니다."
IMPACT_LEVEL="HIGH"

# IPv4 / IPv6 전체 허용 여부 점검
open_ipv4=$(grep -E "^[^#].*0.0.0.0/0" /var/lib/pgsql/data/pg_hba.conf)
open_ipv6=$(grep -E "^[^#].*::/0" /var/lib/pgsql/data/pg_hba.conf)

if [ -n "$open_ipv4" ] || [ -n "$open_ipv6" ]; then
  STATUS="취약"
   EVIDENCE="전체 IP(0.0.0.0/0 또는 ::/0) 접근 허용 설정 존재"
else
  STATUS="양호"
   EVIDENCE="지정된 IP 대역에서만 DB 접속 허용"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"pg_hba.conf에서 전체 IP 허용 설정을 제거하고, DB 접근이 필요한 특정 IP 또는 IP 대역만 허용하도록 설정하십시오. 설정 변경 후 PostgreSQL 서비스를 재시작해야 합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE" 
}
EOF
