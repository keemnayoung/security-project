# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 비밀번호 재사용 제한 정책
# @Description : 비밀번호 변경 시 이전 비밀번호를 재사용할 수 없도록 비밀번호 제약 설정이 되어있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-05"
CATEGORY="계정 관리"
TITLE="비밀번호 재사용 제한 설정"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="취약"
EVIDENCE="PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 운영 절차 또는 외부 인증 정책에 따른 관리 여부를 수동으로 확인할 필요가 있다."

TARGET_FILE="password"
ACTION_IMPACT="PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 해당없습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 해당없습니다.",
  "target_file": "$TARGET_FILE",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",
  "check_date": "$DATE"
}
EOF