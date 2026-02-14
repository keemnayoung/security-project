#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
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
CHECK_COMMAND='systemctl is-active named; systemctl list-units --type=service | grep -E "^(named|named-chroot)\.service"; named -v; command -v named; rpm -q bind bind-chroot; dnf -q info bind 2>/dev/null'

VULNERABLE=0
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
    # cur < req
    return 1
  else
    # cur > req
    return 0
  fi
}

# -----------------------------
# 1) DNS 서비스(named) 활성화 여부 확인
# -----------------------------
DNS_ACTIVE="N"
if systemctl is-active --quiet named 2>/dev/null; then
  DNS_ACTIVE="Y"
elif systemctl is-active --quiet named-chroot 2>/dev/null; then
  DNS_ACTIVE="Y"
fi

# list-units에서도 확인(참고용)
UNIT_LIST_HIT="N"
systemctl list-units --type=service 2>/dev/null | grep -qE '^(named|named-chroot)\.service' && UNIT_LIST_HIT="Y"

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
  # named 명령이 없으면 DNS(BIND) 자체가 없다고 판단(서비스도 보통 없음)
  append_detail "[bind] named_command=NOT_FOUND"
fi

# -----------------------------
# 3) 판정 로직 (U-15~U-16 톤)
# -----------------------------
if [ "$DNS_ACTIVE" = "N" ] && [ $FOUND_ANY -eq 0 ]; then
  # 서비스 비활성 + 바이너리도 없음 => 대상 없음에 가까움(양호 처리)
  STATUS="PASS"
  REASON_LINE="DNS 서비스(named)가 설치되어 있지 않거나 실행되지 않아 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  # 서비스 상태/정보 상세 기록
  append_detail "[service] named_active=$DNS_ACTIVE (unit_list_hit=$UNIT_LIST_HIT)"

  if [ "$DNS_ACTIVE" = "Y" ]; then
    # 실행 중이면 버전 확인 필수
    if [ $FOUND_ANY -eq 0 ] || [ -z "$DNS_VER_RAW" ] || [ "$DNS_VER_RAW" = "unknown" ]; then
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="DNS 서비스가 실행 중이나 버전을 확인할 수 없어 취약합니다. 보안 패치 적용 여부를 확인하기 위해 BIND 버전을 점검하고 최신 보안 업데이트를 적용해야 합니다."
    else
      ver_is_ge "$DNS_VER_RAW" "$REQUIRED_VERSION"
      rc=$?
      if [ $rc -eq 1 ]; then
        STATUS="FAIL"
        VULNERABLE=1
        REASON_LINE="DNS 서비스 버전이 기준에 미달하여 취약합니다. 최신 보안 패치를 적용하고 서비스를 재시작하는 등 패치 관리 정책을 수립하여 주기적으로 적용해야 합니다."
        append_detail "[result] version_check=LOW (current=$(extract_ver "$DNS_VER_RAW") < required=$REQUIRED_VERSION)"
      elif [ $rc -eq 2 ]; then
        STATUS="FAIL"
        VULNERABLE=1
        REASON_LINE="DNS 서비스가 실행 중이나 버전 형식을 정상적으로 확인할 수 없어 취약으로 판단합니다. 현재 버전을 확인한 뒤 최신 보안 업데이트 적용 여부를 점검해야 합니다."
        append_detail "[result] version_check=UNKNOWN (parse_failed)"
      else
        STATUS="PASS"
        REASON_LINE="DNS 서비스 버전이 기준 이상으로 확인되어 이 항목에 대한 보안 위협이 없습니다."
        append_detail "[result] version_check=OK (current=$(extract_ver "$DNS_VER_RAW") >= required=$REQUIRED_VERSION)"
      fi
    fi
  else
    # 비활성 상태면 양호(단, 설치는 되어 있을 수 있음)
    STATUS="PASS"
    REASON_LINE="DNS 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
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