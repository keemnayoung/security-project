#!/bin/bash
# @Author: 한은결
# D-25: 주기적 보안 패치 및 벤더 권고 사항 적용
ID="D-25"
CATEGORY="패치 관리"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

CMD_TIMEOUT=900
MYSQL_TIMEOUT=10
MYSQL_CMD="mysql -u root -pqwer1234!AA --protocol=TCP -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

# 기본은 자동 업데이트 수행
AUTO_UPDATE="${AUTO_UPDATE:-Y}"
RESTART_MYSQL="${RESTART_MYSQL:-Y}"
VENDOR_LATEST_VERSION="${VENDOR_LATEST_VERSION:-}"
PACKAGE_NAME="${PACKAGE_NAME:-}"

run_cmd() {
  local cmd="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${CMD_TIMEOUT}s bash -lc "$cmd" 2>/dev/null
  else
    bash -lc "$cmd" 2>/dev/null
  fi
}

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
}

extract_semver() {
  local v="$1"
  echo "$v" | grep -Eo '[0-9]+(\.[0-9]+){1,3}' | head -n 1
}

version_ge() {
  local a="$1"
  local b="$2"
  [[ -z "$a" || -z "$b" ]] && return 1
  local first
  first="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)"
  [[ "$first" == "$b" ]]
}

detect_pm() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  else
    echo "unknown"
  fi
}

is_pkg_installed() {
  local pm="$1"
  local pkg="$2"
  case "$pm" in
    apt)
      dpkg -s "$pkg" >/dev/null 2>&1
      ;;
    dnf|yum|zypper)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

detect_package_name() {
  local pm="$1"
  local candidates=("mysql-community-server" "mysql-server" "mariadb-server")

  local p
  for p in "${candidates[@]}"; do
    if is_pkg_installed "$pm" "$p"; then
      echo "$p"
      return
    fi
  done

  case "$pm" in
    apt) echo "mysql-server" ;;
    dnf|yum|zypper) echo "mysql-community-server" ;;
    *) echo "mysql-server" ;;
  esac
}

get_candidate_version() {
  local pm="$1"
  local pkg="$2"

  case "$pm" in
    apt)
      run_cmd "apt-cache policy ${pkg} | awk '/Candidate:/{print \$2; exit}'"
      ;;
    dnf)
      run_cmd "dnf -q info ${pkg} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=""){print v"-"r}}'"
      ;;
    yum)
      run_cmd "yum -q info ${pkg} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=""){print v"-"r}}'"
      ;;
    zypper)
      run_cmd "zypper -q info ${pkg} | awk -F': ' '/^Version/{print \$2; exit}'"
      ;;
    *)
      echo ""
      ;;
  esac
}

do_update() {
  local pm="$1"
  local pkg="$2"

  case "$pm" in
    apt)
      run_cmd "DEBIAN_FRONTEND=noninteractive apt-get update -y" >/dev/null || return 1
      run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade ${pkg}" >/dev/null || \
      run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkg}" >/dev/null
      ;;
    dnf)
      run_cmd "dnf -y upgrade ${pkg}" >/dev/null || run_cmd "dnf -y install ${pkg}" >/dev/null
      ;;
    yum)
      run_cmd "yum -y update ${pkg}" >/dev/null || run_cmd "yum -y install ${pkg}" >/dev/null
      ;;
    zypper)
      run_cmd "zypper -n up ${pkg}" >/dev/null || run_cmd "zypper -n in ${pkg}" >/dev/null
      ;;
    *)
      return 1
      ;;
  esac
}

restart_mysql() {
  if [[ "$RESTART_MYSQL" != "Y" ]]; then
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart mysqld >/dev/null 2>&1 || systemctl restart mysql >/dev/null 2>&1
    return $?
  fi

  service mysqld restart >/dev/null 2>&1 || service mysql restart >/dev/null 2>&1
}

OLD_VER="$(run_mysql "SELECT VERSION();")"
RC0=$?
if [[ $RC0 -ne 0 || -z "$OLD_VER" ]]; then
  ACTION_LOG="조치 실패: 현재 MySQL 버전을 확인할 수 없습니다."
  EVIDENCE="SELECT VERSION() 실행 실패"
else
  PM="$(detect_pm)"
  if [[ "$PM" == "unknown" ]]; then
    ACTION_LOG="조치 실패: 지원되는 패키지 매니저(apt/dnf/yum/zypper)를 찾지 못했습니다."
    EVIDENCE="자동 패치 적용 환경을 확인할 수 없습니다."
  else
    if [[ -z "$PACKAGE_NAME" ]]; then
      PACKAGE_NAME="$(detect_package_name "$PM")"
    fi

    CANDIDATE_VER="$(get_candidate_version "$PM" "$PACKAGE_NAME")"
    OLD_SEMVER="$(extract_semver "$OLD_VER")"
    CAND_SEMVER="$(extract_semver "$CANDIDATE_VER")"
    VENDOR_SEMVER="$(extract_semver "$VENDOR_LATEST_VERSION")"

    REF_VER=""
    REF_LABEL=""
    if [[ -n "$VENDOR_SEMVER" ]]; then
      REF_VER="$VENDOR_SEMVER"
      REF_LABEL="벤더 최신 버전(${VENDOR_LATEST_VERSION})"
    elif [[ -n "$CAND_SEMVER" ]]; then
      REF_VER="$CAND_SEMVER"
      REF_LABEL="저장소 후보 버전(${CANDIDATE_VER})"
    fi

    if [[ "$AUTO_UPDATE" != "Y" ]]; then
      ACTION_LOG="조치 미수행: AUTO_UPDATE=N 설정으로 자동 패치를 수행하지 않았습니다."
      EVIDENCE="현재 버전=${OLD_VER}, 기준=${REF_LABEL:-N/A}"
    else
      do_update "$PM" "$PACKAGE_NAME"
      UPD_RC=$?

      if [[ $UPD_RC -ne 0 ]]; then
        ACTION_LOG="조치 실패: MySQL 패키지 업데이트 명령 실행에 실패했습니다."
        EVIDENCE="패키지 매니저=${PM}, 패키지=${PACKAGE_NAME}"
      else
        restart_mysql >/dev/null 2>&1 || true

        NEW_VER="$(run_mysql "SELECT VERSION();")"
        RCN=$?
        if [[ $RCN -ne 0 || -z "$NEW_VER" ]]; then
          ACTION_LOG="조치 일부 실패: 업데이트 후 MySQL 버전 재확인에 실패했습니다."
          EVIDENCE="업데이트 명령은 수행되었으나 버전 검증 실패"
        else
          NEW_SEMVER="$(extract_semver "$NEW_VER")"

          if [[ -n "$REF_VER" && -n "$NEW_SEMVER" ]] && ! version_ge "$NEW_SEMVER" "$REF_VER"; then
            ACTION_LOG="조치 일부 실패: 업데이트를 수행했지만 기준 버전에 도달하지 못했습니다."
            EVIDENCE="업데이트 전=${OLD_VER}, 업데이트 후=${NEW_VER}, 기준=${REF_LABEL}"
          else
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="MySQL 보안 패치 업데이트를 수행하고 버전을 재확인했습니다."
            EVIDENCE="업데이트 전=${OLD_VER}, 업데이트 후=${NEW_VER}, 기준=${REF_LABEL:-N/A}"
          fi
        fi
      fi
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
  "guide":"최신 보안 패치 버전 유지 및 벤더 권고 적용",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON
