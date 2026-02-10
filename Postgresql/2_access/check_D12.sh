# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-12
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 안전한 리스너 비밀번호 설정 및 사용
# @Description : 오라클 데이터베이스 Listener의 비밀번호 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-12"
CATEGORY="접근관리"
TITLE="안전한 리스너 비밀번호 설정 및 사용"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="Oracle DB Listener 보안 항목으로 PostgreSQL에는 적용되지 않음"
TARGET_FILE="Listener"
ACTION_IMPACT="PostgreSQL은 리스너를 이용한 비밀번호 설정 기능을 제공하지 않아 해당없습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide": "PostgreSQL은 리스너를 이용한 비밀번호 설정 기능을 제공하지 않아 해당없습니다.",
  "target_file":"$TARGET_FILE",
  "action_impact":"$ACTION_IMPACT",
  "impact_level":"$IMPACT_LEVEL",
  "check_date": "$DATE"
}
EOF
