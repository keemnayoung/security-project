#!/bin/bash
# @Author: 한은결
# D-21: 인가되지 않은 GRANT OPTION 사용 제한
ID="D-21"
CATEGORY="옵션 관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
ALLOWED_USERS_CSV="${ALLOWED_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
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

sql_escape() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "%s" "$s"
}

QUERY="SELECT User,Host FROM mysql.user WHERE Grant_priv='Y';"
ROWS="$(run_mysql "$QUERY")"
RC=$?
if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 권한 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 권한 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-21 조치를 수행할 수 없습니다."
else
  TARGETS=""
  COUNT=0
  while IFS=$'\t' read -r user host; do
    [[ -z "$host" ]] && continue
    in_csv "$user" "$ALLOWED_USERS_CSV" && continue

    row="${user}"$'\t'"${host}"
    if [[ -z "$TARGETS" ]]; then
      TARGETS="$row"
    else
      TARGETS+=$'\n'"$row"
    fi
    COUNT=$((COUNT + 1))
  done <<< "$ROWS"

  if [[ $COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="비인가 계정의 GRANT OPTION이 없어 추가 조치가 필요하지 않습니다."
    EVIDENCE="D-21 기준 추가 조치 불필요"
  else
    FAIL=0
    APPLIED=0

    while IFS=$'\t' read -r user host; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      run_mysql "REVOKE GRANT OPTION ON *.* FROM '${esc_user}'@'${esc_host}';" >/dev/null
      if [[ $? -ne 0 ]]; then
        run_mysql "UPDATE mysql.user SET Grant_priv='N' WHERE User='${esc_user}' AND Host='${esc_host}';" >/dev/null || FAIL=1
      fi
      APPLIED=$((APPLIED + 1))
    done <<< "$TARGETS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

    VERIFY_ROWS="$(run_mysql "$QUERY")"
    RCV=$?
    REMAIN=0
    SAMPLE="N/A"
    if [[ $RCV -eq 0 ]]; then
      while IFS=$'\t' read -r user host; do
        [[ -z "$host" ]] && continue
        in_csv "$user" "$ALLOWED_USERS_CSV" && continue
        REMAIN=1
        if [[ "$SAMPLE" == "N/A" ]]; then
          SAMPLE="${user}@${host}"
        fi
      done <<< "$VERIFY_ROWS"
    else
      REMAIN=1
      SAMPLE="재검증 조회 실패"
    fi

    if [[ $FAIL -eq 0 && $REMAIN -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="비인가 계정 GRANT OPTION ${APPLIED}건을 회수했습니다."
      EVIDENCE="D-21 조치 후 비인가 GRANT OPTION 미검출"
    else
      ACTION_LOG="조치 일부 실패: 일부 계정의 GRANT OPTION이 남아 있을 수 있습니다."
      EVIDENCE="D-21 자동 조치를 완료하지 못했습니다. (예: ${SAMPLE})"
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
  "guide":"비인가 계정의 GRANT OPTION 회수 및 역할 기반 권한 위임",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
