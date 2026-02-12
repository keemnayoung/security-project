#!/bin/bash
# @Author: 한은결
# D-07: root 권한으로 서비스 구동 제한
ID="D-07"
CATEGORY="계정 관리"
TITLE="root 권한으로 서비스 구동 제한"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_RUN_USER="${MYSQL_RUN_USER:-mysql}"
MY_CNF="${MY_CNF:-}"

find_my_cnf() {
  if [[ -n "$MY_CNF" ]]; then
    printf "%s" "$MY_CNF"
    return
  fi

  local candidates=(
    "/etc/my.cnf"
    "/etc/mysql/my.cnf"
    "/etc/my.cnf.d/mysql-server.cnf"
    "/etc/mysql/mysql.conf.d/mysqld.cnf"
  )

  local f
  for f in "${candidates[@]}"; do
    if [[ -f "$f" ]]; then
      printf "%s" "$f"
      return
    fi
  done

  printf "/etc/my.cnf"
}

ensure_mysqld_user_setting() {
  local file="$1"
  local run_user="$2"
  local tmp
  tmp="$(mktemp)"

  if ! grep -qi '^[[:space:]]*\[mysqld\]' "$file" 2>/dev/null; then
    {
      cat "$file"
      printf "\n[mysqld]\nuser=%s\n" "$run_user"
    } > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
    return 0
  fi

  awk -v run_user="$run_user" '
    BEGIN { in_mysqld=0; done=0 }
    /^[[:space:]]*\[/ {
      if (in_mysqld && !done) {
        print "user=" run_user
        done=1
      }
      in_mysqld = ($0 ~ /^[[:space:]]*\[mysqld\][[:space:]]*$/)
      print
      next
    }
    {
      if (in_mysqld && $0 ~ /^[[:space:]]*user[[:space:]]*=/) {
        if (!done) {
          print "user=" run_user
          done=1
        }
        next
      }
      print
    }
    END {
      if (in_mysqld && !done) {
        print "user=" run_user
      }
    }
  ' "$file" > "$tmp" && cat "$tmp" > "$file"

  rm -f "$tmp"
  return 0
}

is_root_mysqld_running() {
  ps -eo user,comm,args 2>/dev/null | awk '/[m]ysqld/ {print $1}' | grep -qx 'root'
}

any_mysqld_running() {
  ps -eo comm,args 2>/dev/null | awk '/[m]ysqld/ {found=1} END{exit !found}'
}

restart_mysql_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart mysqld >/dev/null 2>&1 || systemctl restart mysql >/dev/null 2>&1
    return $?
  fi

  service mysqld restart >/dev/null 2>&1 || service mysql restart >/dev/null 2>&1
  return $?
}

if ! any_mysqld_running; then
  ACTION_LOG="조치 실패: mysqld 프로세스를 찾을 수 없어 구동 계정 조치를 수행할 수 없습니다."
  EVIDENCE="MySQL 서비스가 실행 중이 아니거나 프로세스 조회에 실패했습니다."
elif ! is_root_mysqld_running; then
  STATUS="PASS"
  ACTION_RESULT="NOT_REQUIRED"
  ACTION_LOG="MySQL 서비스가 이미 root가 아닌 계정으로 실행 중입니다."
  EVIDENCE="D-07 기준 추가 조치 불필요"
else
  CONF_FILE="$(find_my_cnf)"
  CONF_DIR="$(dirname "$CONF_FILE")"
  BACKUP="${CONF_FILE}.bak_$(date +%Y%m%d_%H%M%S)"

  mkdir -p "$CONF_DIR" 2>/dev/null || true
  [[ -f "$CONF_FILE" ]] || touch "$CONF_FILE"

  cp -p "$CONF_FILE" "$BACKUP" 2>/dev/null || true
  ensure_mysqld_user_setting "$CONF_FILE" "$MYSQL_RUN_USER"

  if restart_mysql_service; then
    sleep 1
    if is_root_mysqld_running; then
      ACTION_LOG="조치 일부 실패: 설정은 변경했지만 mysqld가 여전히 root로 실행 중입니다."
      EVIDENCE="설정 파일(${CONF_FILE})에 user=${MYSQL_RUN_USER}를 반영했으나 런타임 반영이 확인되지 않았습니다."
    else
      STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      ACTION_LOG="my.cnf의 [mysqld] user를 ${MYSQL_RUN_USER}로 설정하고 서비스를 재시작했습니다."
      EVIDENCE="D-07 조치 후 mysqld가 root가 아닌 계정으로 실행됩니다."
    fi
  else
    if [[ -f "$BACKUP" ]]; then
      cp -p "$BACKUP" "$CONF_FILE" 2>/dev/null || true
      restart_mysql_service >/dev/null 2>&1 || true
    fi
    ACTION_LOG="조치 실패: MySQL 서비스 재시작에 실패하여 설정을 원복했습니다."
    EVIDENCE="설정 변경 후 서비스 재기동 실패"
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
  "guide":"MySQL 서비스를 root가 아닌 전용 계정(mysql)으로 구동",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
