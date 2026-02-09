# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정
# @Description : DBMS 설정 중 일정 횟수의 로그인 실패 시 계정 잠금 정책에 대한 설정이 되어있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-08"
CURRENT_STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="취약: PostgreSQL은 로그인 실패 횟수 기반 계정 잠금 기능을 DBMS 자체적으로 제공하지 않습니다.  1)PAM 인증 연계를 통한 OS 계정 잠금 정책 적용 2) fail2ban을 이용한 로그인 실패 IP 차단 방식의 보완 통제를 적용"
NOW=$(date '+%Y-%m-%d %H:%M:%S')

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
