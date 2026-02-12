# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash

ID="D-02"
CATEGORY="계정관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
IMPORTANCE="상"
DATE=$(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="pg_roles"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="전체 계정 및 역할을 검토하여 불필요 계정을 수동으로 제거해야 합니다."

STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="전체 계정 검토 필요"
EVIDENCE="N/A"

#########################################
# 1. 모든 ROLE 출력
#########################################

ALL_ROLES=$(sudo -u postgres psql -t -A -F ',' -c "
SELECT rolname,
       rolcanlogin,
       rolsuper,
       rolcreatedb,
       rolcreaterole
FROM pg_roles
ORDER BY rolname;
" 2>/dev/null | sed '/^\s*$/d')

#########################################
# 2. 불필요 계정 후보 생성
#  - 로그인 가능
#  - postgres 제외
#  - pg_ 시스템 역할 제외
#########################################

CANDIDATES=$(sudo -u postgres psql -t -A -c "
SELECT rolname
FROM pg_roles
WHERE rolcanlogin = true
  AND rolname NOT IN ('postgres')
  AND rolname NOT LIKE 'pg_%'
ORDER BY rolname;
" 2>/dev/null | sed '/^\s*$/d' | tr '\n' ',' | sed 's/,$//')

#########################################
# 3. Evidence 구성
#########################################

if [ -z "$ALL_ROLES" ]; then
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="ROLE 조회 실패"
    EVIDENCE="ROLE 정보를 조회할 수 없음"
    GUIDE_MSG="PostgreSQL 접속 권한을 확인한 후 다시 시도하십시오."
else
    EVIDENCE="전체 ROLE 목록 조회 완료"
    GUIDE_MSG="PostgreSQL은 불필요 계정을 자동으로 삭제하지 않습니다. 위 ROLE 목록을 검토하여 운영 및 서비스에 필요하지 않은 계정을 식별하십시오.\n\n※ 조치 대상 후보 계정: ${CANDIDATES}\n\n아래 절차에 따라 수동으로 조치를 수행하십시오.\n\n1) 로그인 차단:\nALTER ROLE <계정명> NOLOGIN;\n\n2) 객체 소유 여부 확인:\nSELECT n.nspname, c.relname\nFROM pg_class c\nJOIN pg_namespace n ON n.oid = c.relnamespace\nWHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname='<계정명>');\n\n3) 소유권 이전:\nREASSIGN OWNED BY <계정명> TO postgres;\n\n4) 최종 삭제:\nDROP ROLE <계정명>;"
fi

#########################################
# 4. JSON 안전 처리
#########################################

EVIDENCE_ESCAPED=$(echo "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
GUIDE_ESCAPED=$(echo "$GUIDE_MSG" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
ACTION_LOG_ESCAPED=$(echo "$ACTION_LOG" | sed 's/"/\\"/g')

#########################################
# 5. JSON 출력
#########################################

cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE_ESCAPED",
  "guide": "$GUIDE_ESCAPED",
  "target_file": "$TARGET_FILE",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG_ESCAPED",
  "check_date": "$DATE"
}
EOF
