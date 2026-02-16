#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# @Criteria_Good : 주기적으로 패치를 관리하는 경우
# @Criteria_Bad : 주기적으로 패치를 관리하고 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-49 DNS 보안 버전 패치

# 기본 변수
ID="U-49"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# ===== 기준 버전 (필요 시 수정) =====
REQUIRED_VERSION="9.20.18"
# ====================================

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/named"
CHECK_COMMAND='systemctl is-active named; systemctl is-active named-chroot; systemctl list-unit-files | grep -E "^(named|named-chroot)\.service"; named -v; command -v named; rpm -q bind bind-chroot; (command -v dnf && dnf -q check-update "bind*" || command -v yum && yum -q check-update "bind*") 2>/dev/null'

FOUND_ANY=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

# 버전 숫자(최소 x.y.z) 추출
extract_ver() {
  echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

# cur >= req 이면 0(양호), cur < req 이면 1(취약), 파싱 실패면 2
ver_is_ge() {
  local cur_raw="$1"
  local req_raw="$2"
  local cur req first
  cur="$(extract_ver "$cur_raw")"
  req="$(extract_ver "$req_raw")"

  if [ -z "$cur" ] || [ -z "$req" ]; then
    return 2
  fi

  first="$(printf "%s\n%s\n" "$cur" "$req" | sort -V | head -n1)"
  if [ "$cur" = "$req" ]; then
    return 0
  elif [ "$first" = "$cur" ]; then
    return 1
  else
    return 0
  fi
}

# -----------------------------
# 1) DNS 서비스(named) 활성화 여부 확인
# -----------------------------
DNS_ACTIVE="N"
ACTIVE_UNIT="none"

if systemctl is-active --quiet named 2>/dev/null; then
  DNS_ACTIVE="Y"
  ACTIVE_UNIT="named.service"
elif systemctl is-active --quiet named-chroot 2>/dev/null; then
  DNS_ACTIVE="Y"
  ACTIVE_UNIT="named-chroot.service"
fi

UNIT_FILE_HIT="N"
systemctl list-unit-files 2>/dev/null | grep -qE '^(named|named-chroot)\.service' && UNIT_FILE_HIT="Y"

# -----------------------------
# 2) named 버전/경로/패키지 정보 수집
# -----------------------------
DNS_VER_RAW=""
NAMED_PATH=""
BIND_RPM=""

if command -v named >/dev/null 2>&1; then
  FOUND_ANY=1
  NAMED_PATH="$(command -v named 2>/dev/null)"
  [ -n "$NAMED_PATH" ] && TARGET_FILE="$NAMED_PATH"

  DNS_VER_RAW="$(named -v 2>/dev/null)"
  [ -z "$DNS_VER_RAW" ] && DNS_VER_RAW="unknown"

  BIND_RPM="$(rpm -q bind bind-chroot 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')"
  [ -z "$BIND_RPM" ] && BIND_RPM="not_installed_or_unknown"

  append_detail "[bind] named_path=$NAMED_PATH"
  append_detail "[bind] named_version_raw=$DNS_VER_RAW"
  append_detail "[bind] required_version=$REQUIRED_VERSION"
  append_detail "[bind] rpm=$BIND_RPM"
else
  append_detail "[bind] named_command=NOT_FOUND"
fi

# -----------------------------
# 3) 최신 패치 적용 여부(업데이트 대기) 확인  ★필수 보강
# -----------------------------
UPDATE_PENDING="unknown"
UPDATE_LINES=""

if [ $FOUND_ANY -eq 1 ]; then
  if command -v dnf >/dev/null 2>&1; then
    UPDATE_LINES="$(dnf -q check-update "bind*" 2>/dev/null | head -n 30)"
    rc=$?
    if [ $rc -eq 100 ]; then
      UPDATE_PENDING="yes"
    elif [ $rc -eq 0 ]; then
      UPDATE_PENDING="no"
    else
      UPDATE_PENDING="unknown"
    fi
  elif command -v yum >/dev/null 2>&1; then
    UPDATE_LINES="$(yum -q check-update "bind*" 2>/dev/null | head -n 30)"
    rc=$?
    if [ $rc -eq 100 ]; then
      UPDATE_PENDING="yes"
    elif [ $rc -eq 0 ]; then
      UPDATE_PENDING="no"
    else
      UPDATE_PENDING="unknown"
    fi
  else
    UPDATE_PENDING="unknown"
  fi

  append_detail "[patch] update_pending=$UPDATE_PENDING"
  [ -n "$UPDATE_LINES" ] && append_detail "[patch] check_update_head=$(echo "$UPDATE_LINES" | tr '\n' ';' | sed 's/[[:space:]]\+/ /g' | sed 's/;/ | /g')"
fi

# -----------------------------
# 4) 판정 로직 (요청 문구 반영)
# -----------------------------
if [ "$DNS_ACTIVE" = "N" ] && [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="DNS 서비스(BIND/named)가 설치되어 있지 않거나 systemd에서 활성화되어 있지 않아 점검 대상이 없으며, 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  append_detail "[service] named_active=$DNS_ACTIVE (active_unit=$ACTIVE_UNIT, unit_file_hit=$UNIT_FILE_HIT)"

  # 업데이트가 대기 중이면(=패치 미적용 가능성) 취약 처리(필수 보강)
  if [ "$UPDATE_PENDING" = "yes" ]; then
    STATUS="FAIL"
    REASON_LINE="패키지 관리자(dnf/yum) 기준 bind 업데이트가 남아 있어 최신 보안 패치가 적용되지 않은 상태로 취약합니다. 조치: (DNS 사용 시) dnf/yum update bind\\* 적용 후 $ACTIVE_UNIT 재시작, (DNS 미사용 시) named 서비스 stop/disable로 비활성화하세요."
  else
    if [ "$DNS_ACTIVE" = "Y" ]; then
      if [ $FOUND_ANY -eq 0 ] || [ -z "$DNS_VER_RAW" ] || [ "$DNS_VER_RAW" = "unknown" ]; then
        STATUS="FAIL"
        REASON_LINE="$ACTIVE_UNIT 가 실행 중이나 named 버전을 확인할 수 없어 취약합니다. 조치: named -v 로 버전 확인 후 최신 보안 패치(dnf/yum update bind\\*) 적용 및 서비스 재시작을 수행하세요."
      else
        ver_is_ge "$DNS_VER_RAW" "$REQUIRED_VERSION"
        rc=$?
        if [ $rc -eq 1 ]; then
          STATUS="FAIL"
          REASON_LINE="$ACTIVE_UNIT 가 실행 중이며 BIND 버전이 $(extract_ver "$DNS_VER_RAW") 로 기준($REQUIRED_VERSION) 미만이라 취약합니다. 조치: dnf/yum update bind\\* 적용 후 $ACTIVE_UNIT 재시작(또는 DNS 미사용 시 stop/disable)하세요."
          append_detail "[result] version_check=LOW (current=$(extract_ver "$DNS_VER_RAW") < required=$REQUIRED_VERSION)"
        elif [ $rc -eq 2 ]; then
          STATUS="FAIL"
          REASON_LINE="$ACTIVE_UNIT 가 실행 중이나 버전 형식을 정상적으로 확인할 수 없어 취약합니다. 조치: 현재 버전 확인 후 최신 보안 패치(dnf/yum update bind\\*) 적용 및 서비스 재시작을 수행하세요."
          append_detail "[result] version_check=UNKNOWN (parse_failed)"
        else
          STATUS="PASS"
          REASON_LINE="$ACTIVE_UNIT 에서 BIND 버전이 $(extract_ver "$DNS_VER_RAW") 로 기준($REQUIRED_VERSION) 이상이며 최신 업데이트 대기 항목이 없어, 이 항목에 대한 보안 위협이 없습니다."
          append_detail "[result] version_check=OK (current=$(extract_ver "$DNS_VER_RAW") >= required=$REQUIRED_VERSION)"
        fi
      fi
    else
      STATUS="PASS"
      REASON_LINE="systemd에서 named 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
    fi
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF