# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : 데이터베이스의 주요 파일들에 대해 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-14"
CATEGORY="접근관리"
TITLE="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="/var/lib/pgsql/data (postgresql.conf, pg_hba.conf, pg_ident.conf)"
ACTION_IMPACT="일반 사용자 계정의 DB 주요 설정 파일 수정이 제한되며, 일반적인 서비스 운영에는 영향이 없습니다."
IMPACT_LEVEL="LOW"

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
  STATUS="PASS"
  EVIDENCE="DB 주요 설정 파일 및 디렉터리 권한이 적절히 제한됨"
else
  STATUS="FAIL"
  EVIDENCE="DB 주요 설정 파일 또는 디렉터리의 권한 설정이 부적절함"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL 데이터 디렉터리 및 주요 설정 파일(postgresql.conf, pg_hba.conf, pg_ident.conf)의 소유자를 postgres 계정으로 설정하고, 일반 사용자 계정의 쓰기 권한을 제거하십시오. 디렉터리는 750 이하, 파일은 640 이하 권한으로 설정하는 것이 권장됩니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE" 
}
EOF
