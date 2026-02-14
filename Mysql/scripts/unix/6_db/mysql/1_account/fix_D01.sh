#!/bin/bash
# @Author: 한은결
# D-01: 기본 계정 비밀번호/잠금 정책 조치
ID="D-01"
CATEGORY="계정 관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

Q1="SELECT user,host,COALESCE(authentication_string,''),COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
Q2="SELECT user,host,COALESCE(authentication_string,''),'N' FROM mysql.user WHERE user='root' OR user='';"
Q3="SELECT user,host,COALESCE(password,''),'N' FROM mysql.user WHERE user='root' OR user='';"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
  ROWS="$(run_mysql "$Q2")"
  RC=$?
fi
if [[ $RC -ne 0 ]]; then
  ROWS="$(run_mysql "$Q3")"
  RC=$?
fi

if [[ $RC -eq 124 ]]; then
  ACTION_LOG="수동 조치 안내: 계정 조회 시간 초과로 자동 판정을 중단했습니다."
  EVIDENCE="mysql.user 조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
  ACTION_RESULT="MANUAL_REQUIRED"
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
  ACTION_LOG="수동 조치 안내: root/기본 계정 조회 실패로 자동 판정을 수행할 수 없습니다."
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-01 조치를 수행할 수 없습니다."
  ACTION_RESULT="MANUAL_REQUIRED"
else
  ROOT_COUNT=0
  VULN_COUNT=0
  REASONS=""

  add_reason() {
    local r="$1"
    if [[ -z "$REASONS" ]]; then
      REASONS="$r"
    else
      REASONS="${REASONS}; ${r}"
    fi
  }

  while IFS=$'\t' read -r user host auth locked; do
    [[ -z "$user" && -z "$host" ]] && continue

    [[ "$locked" == "Y" ]] && is_locked="Y" || is_locked="N"

    # 익명 기본 계정은 잠금/삭제가 되어야 안전
    if [[ -z "$user" ]]; then
      if [[ "$is_locked" != "Y" ]]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        add_reason "anonymous@${host}: 기본(익명) 계정이 활성 상태(잠금/삭제 필요)"
      fi
      continue
    fi

    if [[ "$user" == "root" ]]; then
      ROOT_COUNT=$((ROOT_COUNT + 1))

      # root 비밀번호가 공란이고 잠금도 아니면 취약
      if [[ "$is_locked" != "Y" && -z "$auth" ]]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        add_reason "root@${host}: 비밀번호 미설정(초기/공란) 상태"
        continue
      fi

      # 권한/접근 정책: 원격 root 계정이 활성화되어 있으면 위험
      if [[ "$is_locked" != "Y" ]]; then
        case "$host" in
          localhost|127.0.0.1|::1) : ;;
          *) VULN_COUNT=$((VULN_COUNT + 1)); add_reason "root@${host}: 원격 root 계정 활성(로컬 제한/잠금/삭제 필요)" ;;
        esac
      fi
    fi
  done <<< "$ROWS"

  if [[ "$ROOT_COUNT" -eq 0 ]]; then
    ACTION_LOG="수동 조치 안내: root 기본 계정을 확인할 수 없어 자동 판정 불가"
    EVIDENCE="root 기본 계정을 확인할 수 없어 D-01 판정 불가"
    ACTION_RESULT="MANUAL_REQUIRED"
  elif [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="추가 조치 불필요: 기본 계정(root/익명)의 초기 비밀번호/사용 정책이 기준을 충족합니다."
    EVIDENCE="D-01 양호: 기본 계정의 초기 비밀번호 사용이 확인되지 않고, 불필요한 기본 계정 사용이 제한되어 있습니다."
  else
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 조치 필요: 기본 계정의 초기 비밀번호를 변경하고, 불필요한 기본 계정 사용을 제한해야 합니다."
    EVIDENCE="D-01 취약: ${REASONS}"
  fi
fi

echo ""
cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"MySQL에서는 root 비밀번호를 기관 정책에 맞게 변경하고, 불필요한 root 원격 접속 계정과 익명 계정을 삭제 또는 잠금 처리하며, 비밀번호 변경 시 관련 애플리케이션·배치·모니터링 설정에도 동일하게 반영해야 합니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
