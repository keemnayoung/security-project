#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-08"
CATEGORY=""
CHECK_ITEM="안전한 암호화 알고리즘 사용"
DESCRIPTION="SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="수동진단"
RESULT_MSG=""
CHECKED=true

MYSQL_CMD="mysql -N -B -uroot"

############################################
# 1. MySQL 접속 및 인증 플러그인 확인
############################################
plugin=$($MYSQL_CMD -e "SELECT plugin FROM mysql.user WHERE user='root' AND host='localhost';" 2>/dev/null || true)

if [ -z "$plugin" ]; then
    STATUS="수동진단"
    RESULT_MSG="MySQL 접속 실패 또는 인증 플러그인 확인 불가"

else
############################################
# 2. 안전 알고리즘 여부 판단
############################################
    case "$plugin" in
        caching_sha2_password)
            STATUS="양호"
            RESULT_MSG="SHA-256 기반 인증 방식 사용 (${plugin})"
            ;;
        sha256_password)
            STATUS="양호"
            RESULT_MSG="SHA-256 인증 방식 사용 (${plugin})"
            ;;
        mysql_native_password)
            STATUS="취약"
            RESULT_MSG="SHA-1 기반 인증 방식 사용 (${plugin})"
            ;;
        *)
            STATUS="수동진단"
            RESULT_MSG="알 수 없는 인증 플러그인 사용 (${plugin})"
            ;;
    esac
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
