#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
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

# TIMEOUT_BIN이 비어 있으면 timeout을 사용하지 않고 mysql만 실행
TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# mysql.user의 plugin 값을 조회하여 계정별 인증 플러그인(암호화/인증 방식)을 확인합니다.
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
    REASON_LINE="계정의 암호화 알고리즘 정보를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태 및 접속 환경을 확인해주시기 바랍니다.\n조치 방법은 DB 상태/부하를 점검하신 후 재시도해주시기 바랍니다."
    DETAIL_CONTENT="제한 시간은 ${MYSQL_TIMEOUT}초로 설정되어 있습니다(timeout_sec=${MYSQL_TIMEOUT})."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패로 인해 암호화 알고리즘 사용 여부를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해주시기 바랍니다.\n조치 방법은 접속 계정의 권한과 인증 정보를 확인해주시기 바랍니다."
    DETAIL_CONTENT="MySQL 접속 상태는 실패로 확인되었습니다(mysql_access=FAILED)."
else
    # caching_sha2_password(MySQL 8 기본, SHA-256 기반)가 아닌 계정을 약한 알고리즘 사용 계정으로 간주합니다(원본 판정 기준 유지).
    WEAK_USERS=$(echo "$RESULT" | awk '$3!="caching_sha2_password"{print $1"@"$2"("$3")"}')

    if [[ -z "$WEAK_USERS" ]]; then
        STATUS="PASS"
        REASON_LINE="모든 DB 계정이 SHA-256 기반의 안전한 암호화 알고리즘을 사용하고 있어 비밀번호 탈취 및 무차별 대입 공격 위험이 낮으므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="약한 알고리즘 사용 계정 수는 0건입니다(weak_user_count=0)."
    else
        COUNT=$(echo "$WEAK_USERS" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$WEAK_USERS" | head -n 1)
        STATUS="FAIL"
        REASON_LINE="SHA-256 미만의 암호화 알고리즘을 사용하는 계정이 ${COUNT}건 확인되어 비밀번호 유출 및 계정 탈취 위험이 있습니다.\n조치 방법은 해당 계정의 인증 플러그인을 SHA-256 기반(caching_sha2_password 등)으로 변경해주시기 바라며, 변경 후 적용 여부를 재확인해주시기 바랍니다."
        DETAIL_CONTENT="약한 알고리즘 사용 계정 예시는 ${SAMPLE} 이며, 전체 목록은 $(echo "$WEAK_USERS" | tr '\n' ' ' | sed 's/[[:space:]]*$//') 입니다."
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