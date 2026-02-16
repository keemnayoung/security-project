#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : 접근 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-11"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="information_schema"
EVIDENCE="N/A"

# timeout 미사용(원본 로직 유지)
TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 시스템 스키마 권한(스키마/테이블/전역) 조회
QUERY="
SELECT GRANTEE, 'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE
FROM information_schema.schema_privileges
WHERE TABLE_SCHEMA IN ('mysql','performance_schema','sys','information_schema')
UNION ALL
SELECT GRANTEE, 'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE
FROM information_schema.table_privileges
WHERE TABLE_SCHEMA IN ('mysql','performance_schema','sys','information_schema')
UNION ALL
SELECT GRANTEE, 'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE
FROM information_schema.user_privileges
WHERE PRIVILEGE_TYPE <> 'USAGE';
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    LIST=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    LIST=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

# 허용 계정 목록(기본 DBA/시스템 계정)
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

is_allowed_user() {
    local user="$1"
    IFS=',' read -r -a arr <<< "$ALLOWED_USERS_CSV"
    for u in "${arr[@]}"; do
        [[ "$user" == "$u" ]] && return 0
    done
    return 1
}

# GRANTEE 문자열에서 user 추출
extract_user_from_grantee() {
    echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

REASON_LINE=""
DETAIL_CONTENT=""

if [[ "$LIST" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="시스템 테이블 접근 권한을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 점검을 수행하지 못했습니다.\n조치 방법은 DB 응답 지연 또는 접속 설정을 확인하신 후 재시도해주시기 바랍니다."
    DETAIL_CONTENT="제한 시간은 ${MYSQL_TIMEOUT}초로 설정되어 있습니다(timeout_sec=${MYSQL_TIMEOUT})."
elif [[ "$LIST" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패로 인해 시스템 테이블 접근 권한 점검을 수행할 수 없습니다.\n조치 방법은 진단 계정 권한 및 접속 정보를 확인해주시기 바랍니다."
    DETAIL_CONTENT="MySQL 접속 상태가 확인되지 않았습니다(mysql_access=FAILED)."
else
    if [[ -z "$LIST" ]]; then
        STATUS="PASS"
        REASON_LINE="시스템 스키마(mysql/performance_schema/sys/information_schema) 관련 권한이 일반 사용자에게 부여되어 있지 않으므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="시스템 스키마 관련 권한 조회 결과가 없습니다(no_privileges_found=1)."
    else
        VIOLATION_COUNT=0
        SAMPLE="N/A"

        while IFS=$'\t' read -r grantee scope obj priv; do
            [[ -z "$grantee" ]] && continue
            user="$(extract_user_from_grantee "$grantee")"
            if is_allowed_user "$user"; then
                continue
            fi

            VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
            if [[ "$SAMPLE" == "N/A" ]]; then
                SAMPLE="${grantee} (${scope}:${obj}, ${priv})"
            fi
        done <<< "$LIST"

        if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
            STATUS="PASS"
            REASON_LINE="시스템 스키마(mysql/performance_schema/sys/information_schema) 관련 권한이 허용 계정으로만 제한되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
            DETAIL_CONTENT="허용 계정 외 위반 항목이 확인되지 않았습니다(allowed_only=1). 허용 계정 목록은 ${ALLOWED_USERS_CSV} 입니다."
        else
            STATUS="FAIL"
            REASON_LINE="DBA 외 계정에 시스템 스키마 접근 권한이 부여되어 정보 노출 또는 권한 오남용 위험이 있습니다.\n조치 방법은 일반 계정에 부여된 전역/스키마/테이블 권한을 REVOKE로 회수해주시기 바라며, 업무 DB에 필요한 권한만 최소 범위로 재부여해주시기 바랍니다. 또한 시스템 스키마 권한은 허용 계정(ALLOWED_USERS_CSV)으로만 제한해주시기 바랍니다."
            DETAIL_CONTENT="위반 항목은 ${VIOLATION_COUNT}건이며, 예시는 ${SAMPLE} 입니다. 허용 계정 목록은 ${ALLOWED_USERS_CSV} 입니다."
        fi
    fi
fi

FILE_HASH="N/A(SCHEMA_CHECK)"

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 일반 사용자 계정은 시스템 테이블에 접근할 수 없게 되지만, 지정된 데이터베이스 및 테이블에 대한 권한은 그대로 유지됩니다. 따라서 일반적인 시스템 운영 및 애플리케이션 동작에는 영향이 없으며, 권한 범위를 벗어난 작업 시에만 접근이 제한됩니다."

GUIDE="시스템 스키마(mysql/performance_schema/sys/information_schema) 접근 권한은 허용 계정(ALLOWED_USERS_CSV)으로만 제한하십시오. 일반 계정에 부여된 전역/스키마/테이블 권한은 REVOKE로 회수하고, 업무 DB에 필요한 권한만 최소 범위로 부여하십시오."

CHECK_COMMAND="mysql -N -s -B -e \"${QUERY//$'\n'/ }\""

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
cat << EOF_JSON
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF_JSON