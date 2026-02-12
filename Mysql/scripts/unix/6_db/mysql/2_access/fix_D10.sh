#!/bin/bash
# @Author: 한은결
# D-10: 원격에서 DB 서버로의 접속 제한
ID="D-10"
CATEGORY="접근 관리"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8

MYSQL_CMD="mysql -u root -pqwer1234!AA --protocol=TCP -N -s -B -e"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
ALLOWED_HOSTS_CSV="${ALLOWED_HOSTS_CSV:-localhost,127.0.0.1,::1}"
ACTION_MODE="${ACTION_MODE:-LOCK}" # LOCK | DROP

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql"
  else
    $MYSQL_CMD "$sql"
  fi
  return $?
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

Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
  ROWS="$(run_mysql "$Q2")"
  RC=$?
fi

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="조치 중단: 계정 조회 시간 초과"
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
  ACTION_LOG="조치 실패: 계정 조회 실패"
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-10 조치를 수행할 수 없습니다."
else
  TARGETS=""
  COUNT=0

  while IFS=$'\t' read -r user host locked; do
    [[ -z "$host" ]] && continue
    [[ "$locked" == "Y" ]] && continue

    if in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
      continue
    fi

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
    ACTION_LOG="허용되지 않은 원격 접속 계정이 없어 추가 조치가 필요하지 않습니다."
    EVIDENCE="D-10 기준 추가 조치 불필요"
  else
    FAIL=0
    APPLIED=0

    while IFS=$'\t' read -r user host; do
      [[ -z "$host" ]] && continue
      esc_user="$(sql_escape "$user")"
      esc_host="$(sql_escape "$host")"

      if [[ "$ACTION_MODE" == "DROP" ]]; then
        run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null || FAIL=1
      else
        run_mysql "ALTER USER '${esc_user}'@'${esc_host}' ACCOUNT LOCK;" >/dev/null || FAIL=1
      fi
      APPLIED=$((APPLIED + 1))
    done <<< "$TARGETS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || FAIL=1

    VERIFY_ROWS="$(run_mysql "$Q1")"
    RC2=$?
    if [[ $RC2 -ne 0 ]]; then
      VERIFY_ROWS="$(run_mysql "$Q2")"
      RC2=$?
    fi

    REMAIN=0
    if [[ $RC2 -eq 0 ]]; then
      while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && continue
        in_csv "$host" "$ALLOWED_HOSTS_CSV" && continue
        REMAIN=1
        break
      done <<< "$VERIFY_ROWS"
    else
      REMAIN=1
    fi

    if [[ $FAIL -eq 0 && $REMAIN -eq 0 ]]; then
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="허용되지 않은 원격 접근 계정 ${APPLIED}건을 ${ACTION_MODE} 조치했습니다."
      EVIDENCE="D-10 조치 후 비인가 원격 접근 가능 계정 미검출"
    else
      ACTION_LOG="조치 일부 실패: 허용되지 않은 원격 접근 계정이 일부 남아 있을 수 있습니다."
      EVIDENCE="D-10 자동 조치를 완료하지 못했습니다."
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
  "guide":"허용 호스트 외 계정은 잠금/삭제하여 원격 접속 제한",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
