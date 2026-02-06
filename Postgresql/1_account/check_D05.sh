# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 비밀번호 재사용 제한 정책
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-05"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 재사용 제한 설정"
DESCRIPTION="비밀번호 재사용 제한 정책 적용 여부 점검"
SEVERITY="중"
CHECKED_AT=$(date -Iseconds)

STATUS="취약"
RESULT_MSG="PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 운영 절차 또는 외부 인증 정책에 따른 수동 관리 여부 확인 필요"

cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "severity": "$SEVERITY",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": true
}
EOF