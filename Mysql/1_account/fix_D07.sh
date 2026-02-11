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

ID="D-08"
CATEGORY="계정관리"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --protocol=TCP -uroot -N -s -B -e"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    fi
}

sql_escape_literal() {
    local s="$1"
    s="${s//\'/\'\'}"
    printf "%s" "$s"
}

in_csv() {
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

# 0) 입력값(환경변수) 확인
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"
TARGET_PASS="${TARGET_PASS:-}"
TARGET_ACCOUNTS_CSV="${TARGET_ACCOUNTS_CSV:-}"   # 형식: user@host:password,user2@host2:password2
AUTO_FIX_ALL="${AUTO_FIX_ALL:-N}"                # Y면 취약 계정 전체를 DEFAULT_TARGET_PASS로 일괄 전환
DEFAULT_TARGET_PASS="${DEFAULT_TARGET_PASS:-}"
EXCLUDE_USERS_CSV="${EXCLUDE_USERS_CSV:-mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

# D-08 핵심: 계정별 인증 플러그인을 점검해 SHA-256 미만(비-caching_sha2_password) 계정을 식별한다.
CHECK_SQL="
SELECT user, host, plugin
FROM mysql.user
WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys');
"
ROWS="$(run_mysql "$CHECK_SQL")"
RC1=$?

if [[ $RC1 -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 계정 정보 조회 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC1 -ne 0 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 계정 목록을 조회할 수 없어 인증 방식 전환을 수행하지 못하였습니다."
    EVIDENCE="mysql.user 조회에 실패하여 계정별 암호화 알고리즘 상태를 점검할 수 없습니다."
else
    WEAK_LIST=""
    WEAK_COUNT=0

    while IFS=$'\t' read -r user host plugin; do
        [[ -z "$user" && -z "$host" ]] && continue
        if in_csv "$user" "$EXCLUDE_USERS_CSV"; then
            continue
        fi
        if [[ "$plugin" != "caching_sha2_password" ]]; then
            row="${user}"$'\t'"${host}"$'\t'"${plugin}"
            if [[ -z "$WEAK_LIST" ]]; then
                WEAK_LIST="$row"
            else
                WEAK_LIST="${WEAK_LIST}"$'\n'"${row}"
            fi
            WEAK_COUNT=$((WEAK_COUNT + 1))
        fi
    done <<< "$ROWS"

    if [[ "$WEAK_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="모든 계정이 이미 caching_sha2_password(SHA-256) 기반 인증을 사용하고 있어 추가 조치가 필요하지 않습니다."
        EVIDENCE="계정별 인증 플러그인 점검 결과 SHA-256 이상 알고리즘 기준을 충족합니다."
    else
        TARGETS=""

        if [[ -n "$TARGET_USER" || -n "$TARGET_HOST" || -n "$TARGET_PASS" ]]; then
            if [[ -z "$TARGET_USER" || -z "$TARGET_HOST" || -z "$TARGET_PASS" ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 단일 대상 전환을 위한 입력값이 완전하지 않습니다."
                EVIDENCE="TARGET_USER, TARGET_HOST, TARGET_PASS를 모두 제공해야 대상 계정 전환을 수행할 수 있습니다."
            else
                TARGETS="${TARGET_USER}"$'\t'"${TARGET_HOST}"$'\t'"${TARGET_PASS}"
            fi
        elif [[ -n "$TARGET_ACCOUNTS_CSV" ]]; then
            IFS=',' read -r -a entries <<< "$TARGET_ACCOUNTS_CSV"
            for entry in "${entries[@]}"; do
                [[ -z "$entry" ]] && continue
                account_part="${entry%%:*}"
                pass_part="${entry#*:}"
                user_part="${account_part%@*}"
                host_part="${account_part#*@}"

                if [[ -z "$user_part" || -z "$host_part" || -z "$pass_part" || "$account_part" == "$host_part" || "$entry" == "$pass_part" ]]; then
                    continue
                fi

                row="${user_part}"$'\t'"${host_part}"$'\t'"${pass_part}"
                if [[ -z "$TARGETS" ]]; then
                    TARGETS="$row"
                else
                    TARGETS="${TARGETS}"$'\n'"${row}"
                fi
            done
        elif [[ "$AUTO_FIX_ALL" == "Y" && -n "$DEFAULT_TARGET_PASS" ]]; then
            while IFS=$'\t' read -r user host plugin; do
                [[ -z "$user" && -z "$host" ]] && continue
                row="${user}"$'\t'"${host}"$'\t'"${DEFAULT_TARGET_PASS}"
                if [[ -z "$TARGETS" ]]; then
                    TARGETS="$row"
                else
                    TARGETS="${TARGETS}"$'\n'"${row}"
                fi
            done <<< "$WEAK_LIST"
        else
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 취약 계정 전환 대상 정보가 제공되지 않았습니다."
            EVIDENCE="취약 계정 ${WEAK_COUNT}개가 확인되었습니다. TARGET_USER/TARGET_HOST/TARGET_PASS 또는 TARGET_ACCOUNTS_CSV, AUTO_FIX_ALL+DEFAULT_TARGET_PASS를 제공해야 합니다."
        fi

        if [[ "$STATUS" != "FAIL" ]]; then
            # D-08 핵심: 취약 계정의 인증 플러그인을 caching_sha2_password(SHA-256)로 전환한다.
            APPLIED=0
            FAILED=0
            FAIL_SAMPLE="N/A"

            while IFS=$'\t' read -r user host pass; do
                [[ -z "$user" || -z "$host" || -z "$pass" ]] && continue
                esc_user="$(sql_escape_literal "$user")"
                esc_host="$(sql_escape_literal "$host")"
                esc_pass="$(sql_escape_literal "$pass")"

                FIX_SQL="ALTER USER '${esc_user}'@'${esc_host}' IDENTIFIED WITH caching_sha2_password BY '${esc_pass}';"
                run_mysql "$FIX_SQL" >/dev/null
                RC2=$?

                if [[ $RC2 -eq 0 ]]; then
                    APPLIED=$((APPLIED + 1))
                else
                    FAILED=$((FAILED + 1))
                    [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${user}@${host}"
                fi
            done <<< "$TARGETS"

            # D-08 핵심: 전환 후 전체 계정을 재점검하여 SHA-256 기준 충족 여부를 재검증한다.
            VERIFY_ROWS="$(run_mysql "$CHECK_SQL")"
            RCV=$?
            if [[ $RCV -ne 0 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 부분적으로만 수행되었습니다. 전환 후 검증 조회에 실패했습니다."
                EVIDENCE="인증 플러그인 전환을 수행했지만 재검증을 위한 계정 조회에 실패했습니다."
            else
                REMAIN_WEAK="$(echo "$VERIFY_ROWS" | awk -F'\t' '$1!="" && $3!="caching_sha2_password"{print $1"@"$2"(" $3 ")"}')"
                if [[ -z "$REMAIN_WEAK" && "$FAILED" -eq 0 ]]; then
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="취약 계정의 인증 플러그인을 caching_sha2_password(SHA-256)로 전환해 SHA-256 이상 알고리즘 기준을 충족하도록 조치했습니다."
                    EVIDENCE="전환 성공 ${APPLIED}건, 재검증 결과 모든 계정이 caching_sha2_password를 사용합니다."
                else
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    SAMPLE_REMAIN="$(echo "$REMAIN_WEAK" | head -n 1)"
                    [[ -z "$SAMPLE_REMAIN" ]] && SAMPLE_REMAIN="$FAIL_SAMPLE"
                    ACTION_LOG="조치가 부분적으로만 수행되었습니다. 일부 계정은 SHA-256 기준을 충족하지 못했습니다."
                    EVIDENCE="전환 성공 ${APPLIED}건, 실패 ${FAILED}건이며 미전환 계정이 남아 있습니다. (예: ${SAMPLE_REMAIN})"
                fi
            fi
        fi
    fi
fi

# JSON 표준 출력 (고정 구조)
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인 기준 보안 설정 조치 완료",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
