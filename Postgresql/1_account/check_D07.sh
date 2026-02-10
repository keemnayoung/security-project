# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : 서비스 구동 시 root 계정 또는 root 권한으로 구동되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-07"
CATEGORY="계정 관리"
TITLE="root 권한 서비스 구동 제한"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="account"
ACTION_IMPACT="일반적인 경우 서비스 운영에 영향은 없으나, 계정 설정 변경 시 서비스 재가동이 필요할 수 있습니다."
IMPACT_LEVEL="LOW"

root_cnt=$(ps -eo user,comm | grep postgres | grep -w root | wc -l)
if [ "$root_cnt" -eq 0 ]; then
  STATUS="양호"
  EVIDENCE="PostgreSQL 서비스가 전용 계정(postgres)으로 실행 중"
else
  STATUS="취약"
  EVIDENCE="PostgreSQL 서비스가 root 권한으로 실행 중"
fi

cat <<EOF
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"PostgreSQL 서비스는 root 권한이 아닌 전용 계정(postgres)으로 실행되도록 구성해야 합니다. 서비스 실행 계정을 postgres로 변경한 후, 서비스 재기동을 통해 적용 여부를 확인하십시오.",
  "target_file":"$TARGET_FILE",
  "action_impact":"$ACTION_IMPACT",
  "impact_level":"$IMPACT_LEVEL",
  "check_date": "$DATE"
}
EOF
