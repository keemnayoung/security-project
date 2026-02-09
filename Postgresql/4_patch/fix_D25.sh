# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-25"

CURRENT_STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

CURRENT_VERSION=$(psql -U postgres -t -c "SHOW server_version;" 2>/dev/null | xargs)
MAJOR_VERSION=$(echo "$CURRENT_VERSION" | cut -d'.' -f1)

ACTION_LOG="수동 조치 필요: 현재 PostgreSQL 버전($CURRENT_VERSION)은 보안 패치 지원 여부 점검 대상입니다. 동일 메이저 버전($MAJOR_VERSION.x)의 최신 보안 패치 버전으로 업데이트를 권장합니다. 예: PostgreSQL $MAJOR_VERSION.x → PostgreSQL $MAJOR_VERSION 최신 마이너 버전. 테스트 환경 검증 후 운영 반영하십시오."

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
