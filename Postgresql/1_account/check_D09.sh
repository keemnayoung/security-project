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
ID="D-09"
CATEGORY="계정 관리"
TITLE="로그인 실패 횟수 제한"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="password"
ACTION_IMPACT="PAM 또는 fail2ban을 통한 로그인 실패 제한 정책은 반복적인 인증 실패 시에만 적용되므로,일반적인 서비스 이용 및 정상 사용자 인증에는 영향이 없으며,오탐 방지를 위해 정책 값에 대한 사전 검토가 필요할 수 있습니다."
IMPACT_LEVEL="LOW"
STATUS="취약"
EVIDENCE="PostgreSQL은 로그인 실패 횟수 기반 계정 잠금 기능을 DBMS 자체적으로 제공하지 않습니다."

cat <<EOF
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"운영체제 수준의 인증 통제(PAM) 또는 접근 제어 도구(fail2ban 등)를 활용하여 일정 횟수 이상의 로그인 실패 시 계정 또는 접속을 제한하도록 구성해야 합니다.",
  "target_file":"$TARGET_FILE",
  "action_impact":"$ACTION_IMPACT",
  "impact_level":"$IMPACT_LEVEL",
  "check_date": "$DATE"
}
EOF

