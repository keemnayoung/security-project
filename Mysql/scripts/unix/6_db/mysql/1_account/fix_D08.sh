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
MYSQL_CMD="mysql -u root -pqwer1234!AA --protocol=TCP -N -s -B -e"
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

  # 1️⃣ 취약 플러그인 계정 탐지
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

  # 2️⃣ 이미 모두 안전한 경우
  if [[ $WEAK_COUNT -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="모든 계정이 SHA-256 기반(caching_sha2_password) 인증을 사용 중입니다."
    EVIDENCE="D-08 기준 추가 조치 불필요"
  else
    # 3️⃣ 자동 조치: 익명 계정만 삭제
    DELETED_ANON=0
    FAILED_ANON=0
    FAIL_SAMPLE="N/A"

    while IFS=$'\t' read -r user host plugin; do
      [[ -z "$host" ]] && continue
      esc_host="$(sql_escape "$host")"

      if [[ -z "$user" ]]; then
        run_mysql "DROP USER IF EXISTS ''@'${esc_host}';" >/dev/null
        if [[ $? -eq 0 ]]; then
          DELETED_ANON=$((DELETED_ANON + 1))
        else
          FAILED_ANON=$((FAILED_ANON + 1))
          [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="''@${host}"
        fi
      fi
    done <<< "$WEAK_ROWS"

    run_mysql "FLUSH PRIVILEGES;" >/dev/null || true

    # 4️⃣ 재검증
    VERIFY_ROWS="$(run_mysql "$CHECK_SQL")"
    RCV=$?

    REMAIN_COUNT=0
    SAMPLE_REMAIN=""

    if [[ $RCV -eq 0 ]]; then
      while IFS=$'\t' read -r user host plugin; do
        [[ -z "$host" ]] && continue
        in_csv "$user" "$EXCLUDE_USERS_CSV" && continue

        if [[ "$plugin" != "caching_sha2_password" ]]; then
          REMAIN_COUNT=$((REMAIN_COUNT + 1))
          [[ -z "$SAMPLE_REMAIN" ]] && SAMPLE_REMAIN="${user}@${host}(${plugin})"
        fi
      done <<< "$VERIFY_ROWS"
    else
      REMAIN_COUNT=$WEAK_COUNT
      SAMPLE_REMAIN="$FAIL_SAMPLE"
    fi

    # 5️⃣ 수동 조치 안내
    MANUAL_GUIDE="취약 계정의 인증 플러그인을 SHA-256 기반(caching_sha2_password)으로 수동 전환하십시오. 예) ALTER USER '계정'@'호스트' IDENTIFIED WITH caching_sha2_password BY '새로운비밀번호';"

    if [[ $FAILED_ANON -eq 0 ]]; then
      ACTION_LOG="익명 계정 ${DELETED_ANON}건 삭제 조치를 완료했습니다. 취약 인증 플러그인 계정은 수동 전환이 필요합니다."
    else
      ACTION_LOG="익명 계정 삭제 조치 일부 실패가 발생했습니다. 취약 인증 플러그인 계정은 수동 전환이 필요합니다."
    fi

    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"

    if [[ $REMAIN_COUNT -gt 0 ]]; then
      EVIDENCE="취약 인증 플러그인 계정 ${REMAIN_COUNT}건이 확인됩니다. (예: ${SAMPLE_REMAIN}) ${MANUAL_GUIDE}"
    else
      EVIDENCE="익명 계정 삭제 후 취약 계정 재확인이 필요합니다. ${MANUAL_GUIDE}"
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
  "guide":"취약 계정의 인증 플러그인을 caching_sha2_password로 수동 전환하고, 비밀번호는 기관 정책에 맞게 재설정하시기 바랍니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
