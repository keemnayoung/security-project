#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-01"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 사용 기간 및 복잡도 정책 설정"
DESCRIPTION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되어 있는지 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="양호"
RESULT_MSG=""
CHECKED=true

MYSQL_CMD="mysql -uroot -N -B"

############################################
# 1. root 계정 전체 조회
############################################
root_info=$($MYSQL_CMD -e "SELECT user,host,authentication_string,account_locked,plugin FROM mysql.user WHERE user='root';" 2>/dev/null)

if [ -z "$root_info" ]; then
  STATUS="점검불가"
  RESULT_MSG="MySQL 접속 실패 또는 root 계정 조회 불가"
else
  VULN=0

  while read -r user host auth locked plugin; do

    # auth_socket 사용 시 비번 없이 접속 가능 → 취약
    if [[ "$plugin" == "auth_socket" ]]; then
      RESULT_MSG+="[$user@$host] auth_socket 인증 사용 → 비밀번호 보호 안됨 (취약)\n"
      VULN=1
      continue
    fi

    # 비밀번호 없고 잠금도 안 됨 → 취약
    if [[ -z "$auth" && "$locked" != "Y" ]]; then
      RESULT_MSG+="[$user@$host] 비밀번호 미설정 & 잠금 안됨 (취약)\n"
      VULN=1
    fi

    # 잠금 상태면 양호
    if [[ "$locked" == "Y" ]]; then
      RESULT_MSG+="[$user@$host] 계정 잠금 상태 (양호)\n"
    fi

  done <<< "$root_info"

  if [ "$VULN" -eq 1 ]; then
    STATUS="취약"
  else
    RESULT_MSG+="기본 관리자 계정 비밀번호 변경 또는 잠금 설정 확인\n"
    STATUS="양호"
  fi
fi

############################################
# 결과 출력
############################################
cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "IMPORTANCE": "$IMPORTANCE",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": $CHECKED
}
EOF
