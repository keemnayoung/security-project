#!/bin/bash
# @Author: 한은결
# D-08: 안전한 암호화 알고리즘 사용
ID="D-08"
CATEGORY="계정 관리"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
EXCLUDE_USERS_CSV="${EXCLUDE_USERS_CSV:-mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
}

sql_escape() {
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

gen_pass() {
  local p
  p="$(tr -dc 'A-Za-z0-9@#%+=_' </dev/urandom | head -c 20)"
  [[ ${#p} -lt 12 ]] && p="D08Fix$(date +%s)Aa1!"
  printf "%s" "$p"
}

CHECK_SQL="
SELECT user,host,plugin
FROM mysql.user
WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys');
"

ROWS="$(run_mysql "$CHECK_SQL")"
RC=$?
if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-08 조치를 수행할 수 없습니다."
else
  WEAK_ROWS=""
  WEAK_COUNT=0

  while IFS=$'\t' read -r user host plugin; do
    [[ -z "$host" ]] && continue
    in_csv "$user" "$EXCLUDE_USERS_CSV" && continue

    if [[ "$plugin" != "caching_sha2_password" ]]; then
      row="${user}"$'\t'"${host}"$'\t'"${plugin}"
      if [[ -z "$WEAK_ROWS" ]]; then
        WEAK_ROWS="$row"
      else
        WEAK_ROWS+=$'\n'"$row"
      fi
      WEAK_COUNT=$((WEAK_COUNT + 1))
    fi
  done <<< "$ROWS"

  if [[ $WEAK_COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="모든 계정이 SHA-256 기반(caching_sha2_password) 인증을 사용 중입니다."
    EVIDENCE="D-08 기준 추가 조치 불필요"
  else
    APPLIED=0
    FAILED=0
    FAIL_SAMPLE="N/A"

    while IFS=$'\t' read -r user host plugin; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      if [[ -z "$user" ]]; then
        run_mysql "DROP USER IF EXISTS ''@'${esc_host}';" >/dev/null
        if [[ $? -eq 0 ]]; then
          APPLIED=$((APPLIED + 1))
        else
          FAILED=$((FAILED + 1))
          [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="''@${host}"
        fi
        continue
      fi

      new_pass="$(gen_pass)"
      esc_pass="$(sql_escape "$new_pass")"
      run_mysql "ALTER USER '${esc_user}'@'${esc_host}' IDENTIFIED WITH caching_sha2_password BY '${esc_pass}';" >/dev/null
      if [[ $? -eq 0 ]]; then
        APPLIED=$((APPLIED + 1))
      else
        FAILED=$((FAILED + 1))
        [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${user}@${host}"
      fi
    done <<< "$WEAK_ROWS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || true

    VERIFY_ROWS="$(run_mysql "$CHECK_SQL")"
    RCV=$?
    REMAIN_WEAK=""
    if [[ $RCV -eq 0 ]]; then
      REMAIN_WEAK="$(echo "$VERIFY_ROWS" | awk -F'\t' '$1!="" && $3!="caching_sha2_password" {print $1"@"$2"("$3")"}')"
    fi

    if [[ $RCV -eq 0 && -z "$REMAIN_WEAK" && $FAILED -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="취약 계정 인증 알고리즘을 SHA-256 기반으로 전환했습니다."
      EVIDENCE="전환 성공 ${APPLIED}건, 재검증 결과 취약 계정 없음"
    else
      SAMPLE_REMAIN="$(echo "$REMAIN_WEAK" | head -n 1)"
      [[ -z "$SAMPLE_REMAIN" ]] && SAMPLE_REMAIN="$FAIL_SAMPLE"
      ACTION_LOG="조치 일부 실패: 일부 계정이 SHA-256 기준을 충족하지 못했습니다."
      EVIDENCE="전환 성공 ${APPLIED}건, 실패 ${FAILED}건 (예: ${SAMPLE_REMAIN})"
    fi
  fi
fi

cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"취약 계정의 인증 플러그인을 caching_sha2_password로 전환",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
