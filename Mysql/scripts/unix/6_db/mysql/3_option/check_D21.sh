#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : 옵션 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-21"
CATEGORY="옵션 관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"
TARGET_FILE="mysql.user"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 인가 예외(기관 정책에 따라 확장)
# WITH_GRANT_OPTION은 ROLE 등에 의해 관리되어야 하며, 일반 사용자에게 직접 부여되면 취약
ALLOWED_GRANT_USERS_CSV="${ALLOWED_GRANT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_GRANT_PRINCIPALS_CSV="${ALLOWED_GRANT_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"
ALLOWED_GRANT_GRANTEES_CSV="${ALLOWED_GRANT_GRANTEES_CSV:-}"

in_csv() {
    local needle="$1"
    local csv="$2"
    needle="$(printf "%s" "$needle" | tr '[:upper:]' '[:lower:]')"
    needle="${needle//[[:space:]]/}"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        item="$(printf "%s" "$item" | tr '[:upper:]' '[:lower:]')"
        item="${item//[[:space:]]/}"
        [[ -n "$item" && "$needle" == "$item" ]] && return 0
    done
    return 1
}

extract_user_from_grantee() { echo "$1" | sed -E "s/^'([^']+)'.*$/\\1/"; }
extract_host_from_grantee() { echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\\1/"; }

is_allowed_grantee() {
    local grantee="$1"
    local user host principal

    if [[ -n "$ALLOWED_GRANT_GRANTEES_CSV" ]] && in_csv "$grantee" "$ALLOWED_GRANT_GRANTEES_CSV"; then
        return 0
    fi

    user="$(extract_user_from_grantee "$grantee")"
    host="$(extract_host_from_grantee "$grantee")"
    principal="${user}@${host}"

    in_csv "$user" "$ALLOWED_GRANT_USERS_CSV" && return 0
    in_csv "$principal" "$ALLOWED_GRANT_PRINCIPALS_CSV" && return 0
    return 1
}

# 정보 스키마 기반: WITH GRANT OPTION(=is_grantable=YES) 또는 GRANT OPTION 보유 여부를 점검
Q_IS_TABLE="
SELECT GRANTEE,'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.table_privileges
WHERE IS_GRANTABLE='YES';
"
Q_IS_SCHEMA="
SELECT GRANTEE,'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.schema_privileges
WHERE IS_GRANTABLE='YES';
"
Q_IS_GLOBAL="
SELECT GRANTEE,'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.user_privileges
WHERE IS_GRANTABLE='YES' OR PRIVILEGE_TYPE='GRANT OPTION';
"

run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
    fi
}

R_TABLE="$(run_mysql_query "$Q_IS_TABLE")"
R_SCHEMA="$(run_mysql_query "$Q_IS_SCHEMA")"
R_GLOBAL="$(run_mysql_query "$Q_IS_GLOBAL")"

# Fallback: information_schema 조회가 실패하는 환경은 mysql.user/mysql.db 플래그로 최소 점검
FALLBACK_USED="N"
if [[ "$R_TABLE" == "ERROR" || "$R_SCHEMA" == "ERROR" || "$R_GLOBAL" == "ERROR" ]]; then
    FALLBACK_USED="Y"
    R_TABLE="N/A"
    R_SCHEMA="N/A"
    R_GLOBAL="$(run_mysql_query "SELECT CONCAT(\"'\",User,\"'@'\",Host,\"'\") AS GRANTEE,'GLOBAL' AS SCOPE,'*.*' AS OBJ,'GRANT OPTION' AS PRIVILEGE_TYPE,'YES' AS IS_GRANTABLE FROM mysql.user WHERE Grant_priv='Y';")"
fi

if [[ "$R_TABLE" == "ERROR_TIMEOUT" || "$R_SCHEMA" == "ERROR_TIMEOUT" || "$R_GLOBAL" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="GRANT OPTION 부여 현황을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$R_GLOBAL" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 GRANT OPTION 부여 여부를 확인할 수 없습니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    REASON="N/A"

    check_rows() {
        local rows="$1"
        local default_reason="$2"
        local grantee scope obj priv grantable
        while IFS=$'\t' read -r grantee scope obj priv grantable; do
            [[ -z "$grantee" || -z "$priv" ]] && continue
            if is_allowed_grantee "$grantee"; then
                continue
            fi
            VULN_COUNT=$((VULN_COUNT + 1))
            if [[ "$SAMPLE" == "N/A" ]]; then
                SAMPLE="${grantee} (${scope}:${obj}, ${priv}, grantable=${grantable:-?})"
                REASON="$default_reason"
            fi
        done <<< "$rows"
    }

    [[ "$R_TABLE" != "N/A" ]] && check_rows "$R_TABLE" "테이블 권한 WITH GRANT OPTION"
    [[ "$R_SCHEMA" != "N/A" ]] && check_rows "$R_SCHEMA" "스키마 권한 WITH GRANT OPTION"
    check_rows "$R_GLOBAL" "글로벌 GRANT OPTION/WITH GRANT OPTION"

    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        if [[ "$FALLBACK_USED" == "Y" ]]; then
            EVIDENCE="D-21 양호(제한적 점검): mysql.user(Grant_priv) 기준으로 인가되지 않은 GRANT OPTION이 확인되지 않았습니다."
        else
            EVIDENCE="D-21 양호: 인가되지 않은 계정에 WITH GRANT OPTION/GRANT OPTION이 확인되지 않았습니다."
        fi
    else
        STATUS="FAIL"
        EVIDENCE="D-21 취약: 인가되지 않은 계정/ROLE에 WITH GRANT OPTION(또는 GRANT OPTION)이 부여되어 있습니다. (${VULN_COUNT}건, 사유: ${REASON}, 예: ${SAMPLE})"
    fi
fi

FILE_HASH="N/A(TABLE_CHECK)"

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없습니다. 불필요하거나 과도하게 부여된 권한만 회수되며, 해당 권한을 실제로 사용하지 않던 계정의 정상 업무에는 지장이 없습니다. 다만 회수된 권한이 필요한 특정 관리 작업을 수행할 경우에는 권한 부족으로 작업이 제한될 수 있습니다."

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "일반 사용자에게 직접 부여된 WITH GRANT OPTION/GRANT OPTION을 REVOKE하여 회수하십시오. 권한 위임이 필요하면 ROLE을 생성해 필요한 권한만 WITH GRANT OPTION으로 부여하고, 사용자에는 ROLE만 부여하여 운영하십시오. 인가 예외는 ALLOWED_GRANT_USERS_CSV/ALLOWED_GRANT_PRINCIPALS_CSV/ALLOWED_GRANT_GRANTEES_CSV로 관리하십시오.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
