# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-06"
CATEGORY="계정관리"
TITLE="사용자별 DB 계정 사용"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="password"
ACTION_IMPACT="PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 해당없습니다."
IMPACT_LEVEL="LOW"

login_cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true AND rolname <> 'postgres';" | xargs)

if [ "$login_cnt" -gt 1 ]; then
  STATUS="FAIL"
  EVIDENCE="로그인 가능한 계정이 다수 존재하나 사용자별 계정 사용 여부는 수동 확인 필요"
else
  STATUS="FAIL"
  EVIDENCE="공용 계정 사용 가능성 높음 (로그인 계정 수가 제한적)"
fi

cat <<EOF
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "DB 접근 시 사용자별로 서로 다른 계정을 사용을 권장합니다.",
  "target_file":"$TARGET_FILE",
  "action_impact":"$ACTION_IMPACT",
  "impact_level":"$IMPACT_LEVEL",
  "check_date": "$DATE"
}
EOF
