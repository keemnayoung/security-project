#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-07"
CATEGORY="서비스권한관리"
CHECK_ITEM="root 권한으로 서비스 구동 제한"
DESCRIPTION="DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검"
IMPORTANCE="중"
CHECKED_AT=$(date -Iseconds)

STATUS="수동진단"
RESULT_MSG=""
CHECKED=true

############################################
# 1. MySQL 프로세스 존재 확인
############################################
mysql_user=$(ps -eo user,comm | grep -E 'mysqld|mariadbd' | grep -v grep | awk '{print $1}' | head -1 || true)

if [ -z "$mysql_user" ]; then
    STATUS="수동진단"
    RESULT_MSG="MySQL/MariaDB 프로세스를 찾을 수 없음 — 서비스 상태 수동 확인 필요"

else
############################################
# 2. 실행 계정 확인
############################################
    if [ "$mysql_user" = "root" ]; then
        STATUS="취약"
        RESULT_MSG="MySQL이 root 권한으로 실행 중"
    else
        STATUS="양호"
        RESULT_MSG="MySQL이 '${mysql_user}' 계정으로 실행 중"
    fi
fi

############################################
# 결과 JSON 출력 (필수 형식)
############################################
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
  "checked": $CHECKED
}
EOF
