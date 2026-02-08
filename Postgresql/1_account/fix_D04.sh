# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBMS 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-04"
CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 관리자 권한 허용 계정 화이트리스트
ALLOWED_ADMINS=("postgres" "dbadmin" "backup_user")

# postgres 제외 관리자 권한 계정 조회
ADMIN_ROLES=$(sudo -u postgres psql -t -c "
SELECT rolname
FROM pg_roles
WHERE rolsuper = true
ORDER BY rolname;
" 2>/dev/null | sed '/^\s*$/d')

REMOVED_ROLES=()

for role in $ADMIN_ROLES; do
  SKIP=false
  for allowed in "${ALLOWED_ADMINS[@]}"; do
    if [ "$role" = "$allowed" ]; then
      SKIP=true
      break
    fi
  done

  if [ "$SKIP" = false ]; then
    sudo -u postgres psql -c "
      ALTER ROLE \"$role\" NOSUPERUSER;
      ALTER ROLE \"$role\" NOCREATEROLE;
      ALTER ROLE \"$role\" NOCREATEDB;
      ALTER ROLE \"$role\" NOREPLICATION;
      ALTER ROLE \"$role\" NOBYPASSRLS;
    " >/dev/null 2>&1
    REMOVED_ROLES+=("$role")
  fi
done

if [ ${#REMOVED_ROLES[@]} -eq 0 ]; then
  CURRENT_STATUS="PASS"
  ACTION_RESULT="NOT_REQUIRED"
  ACTION_LOG="양호: 화이트리스트 외 관리자 권한 계정 없음"
else
  CURRENT_STATUS="PASS"
  ACTION_RESULT="SUCCESS"
  ACTION_LOG="자동 조치 완료: 관리자 권한 회수 계정($(IFS=, ; echo "${REMOVED_ROLES[*]}"))"
fi

# JSON 출력
cat <<EOF
{
  "check_id": "$ID",
  "status": "$CURRENT_STATUS",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
