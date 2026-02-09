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
ITEM_ID="D-09"
CATEGORY="계정관리"
CHECK_ITEM="로그인 실패 횟수 제한"
DESCRIPTION="DBMS 설정 중 일정 횟수의 로그인 실패 시 계정 잠금 정책에 대한 설정이 되어있는지 점검"
IMPORTANCE="중"
CHECKED_AT=$(date -Iseconds)

# PostgreSQL은 DBMS 자체적으로 로그인 실패 횟수 기반 계정 잠금 기능을 제공하지 않음
STATUS="취약"
RESULT_MSG="취약: PostgreSQL은 로그인 실패 횟수 기반 계정 잠금 기능을 DBMS 자체적으로 제공하지 않습니다. PAM 또는 fail2ban을 통한 보완 통제 적용 여부는 수동 확인 대상입니다."

cat <<EOF
{
  "item_id":"$ITEM_ID",
  "category":"$CATEGORY",
  "check_item":"$CHECK_ITEM",
  "description":"$DESCRIPTION",
  "IMPORTANCE":"$IMPORTANCE",
  "checked_at":"$CHECKED_AT",
  "status":"$STATUS",
  "result":"$RESULT_MSG",
  "checked":true
}
EOF

