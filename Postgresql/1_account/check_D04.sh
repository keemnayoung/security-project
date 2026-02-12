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
CATEGORY="계정관리"
TITLE="DBMS 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
IMPORTANCE="상"
TARGET_FILE="pg_roles"
ACTION_IMPACT="최소한의 필요한 관리자 권한만 유지하는 조치로 서비스 및 정상 운영에는 영향이 없습니다."
IMPACT_LEVEL="LOW"
DATE=(date '+%Y-%m-%d %H:%M:%S')

cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true AND rolname <> 'postgres';" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="PASS"
   EVIDENCE="postgres 외 불필요한 관리자 권한을 가진 계정이 없습니다."
else
  STATUS="FAIL"
   EVIDENCE="postgres 외 관리자 권한이 부여된 계정이 존재합니다."
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"계정별 용도를 파악한 후 불필요한 계정 삭제하세요."
"target_file": "$TARGET_FILE",
"action_impact": "$ACTION_IMPACT",
"impact_level": "$IMPACT_LEVEL",
"check_date": "$DATE" }
EOF
