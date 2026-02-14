#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-08"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user.plugin"
EVIDENCE="N/A"

# 기존 로직 유지용 변수(출력에는 직접 사용 안 함)
TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 사용자 계정의 인증 플러그인 확인
QUERY="
SELECT user, host, plugin
FROM mysql.user
;
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

REASON_LINE=""
DETAIL_CONTENT=""

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="계정의 암호화 알고리즘 정보를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
    DETAIL_CONTENT="timeout_sec=${MYSQL_TIMEOUT}"
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패로 인해 암호화 알고리즘 사용 여부를 확인할 수 없습니다."
    DETAIL_CONTENT="mysql_access=FAILED"
else
    # SHA-256 미만 알고리즘 사용 계정 확인
    WEAK_USERS=$(echo "$RESULT" | awk '$3!="caching_sha2_password"{print $1"@"$2"("$3")"}')

    if [[ -z "$WEAK_USERS" ]]; then
        STATUS="PASS"
        REASON_LINE="모든 DB 계정이 SHA-256 기반의 안전한 암호화 알고리즘을 사용하고 있어, 비밀번호 탈취 및 무차별 대입 공격 위험이 낮습니다."
        DETAIL_CONTENT="weak_user_count=0"
    else
        COUNT=$(echo "$WEAK_USERS" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$WEAK_USERS" | head -n 1)
        STATUS="FAIL"
        REASON_LINE="SHA-256 미만의 암호화 알고리즘을 사용하는 계정(${COUNT}개)이 존재하여, 비밀번호 유출 및 계정 탈취 위험이 있습니다."
        DETAIL_CONTENT="sample=${SAMPLE}; weak_users=$(echo "$WEAK_USERS" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    fi
fi

CHECK_COMMAND="mysql -N -s -B -e \"SELECT user, host, plugin FROM mysql.user;\""
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF