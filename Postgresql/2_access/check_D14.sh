# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : DB 오류 발생 시 시스템 내부 정보가 과도하게 노출되지 않는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-14"
CATEGORY="접근관리"
CHECK_ITEM="DB 주요 파일 권한"
DESCRIPTION="PostgreSQL 설정 파일 및 데이터 디렉터리 접근 권한 점검"
SEVERITY="중"
CHECKED_AT=$(date -Iseconds)

# PostgreSQL 데이터 디렉터리
PGDATA="/var/lib/pgsql/data"
BAD=0


if [ -d "$PGDATA" ]; then
  dir_perm=$(stat -c %a "$PGDATA")
  dir_owner=$(stat -c %U "$PGDATA")

  if [[ "$dir_perm" -gt 750 || "$dir_owner" != "postgres" ]]; then
    BAD=1
  fi
else
  BAD=1
fi


for f in postgresql.conf pg_hba.conf pg_ident.conf; do
  file="$PGDATA/$f"
  if [ -f "$file" ]; then
    perm=$(stat -c %a "$file")
    owner=$(stat -c %U "$file")
    if [[ "$perm" -gt 640 || "$owner" != "postgres" ]]; then
      BAD=1
    fi
  fi
done

if [ "$BAD" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="DB 주요 설정 파일 및 디렉터리 권한이 적절히 제한됨"
else
  STATUS="취약"
  RESULT_MSG="DB 주요 설정 파일 또는 디렉터리의 권한 설정이 부적절함"
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
