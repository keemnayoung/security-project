#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# @Criteria_Good :  메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-45 메일 서비스 버전 점검


# 1. 항목 정보 정의
ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# ===== 버전 설정 (수정 가능) =====
SENDMAIL_REQUIRED_VERSION="8.18.2"
POSTFIX_REQUIRED_VERSION="3.10.7"
EXIM_REQUIRED_VERSION="4.99.1"
# ==================================

# 2. 진단 로직
STATUS="PASS"
VULNERABLE=0

# 결과 누적용
FINDINGS=()
TARGET_FILES=()
FILE_INFOS=()

# 버전 비교 함수
version_compare() {
  # $1: 현재 버전, $2: 요구 버전
  # 반환: 0 (같음), 1 (현재 > 요구), 2 (현재 < 요구), 3 (파싱 실패)
  local ver1 ver2
  ver1=$(echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  ver2=$(echo "$2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

  [ -z "$ver1" ] || [ -z "$ver2" ] && return 3

  local IFS='.'
  local a=($ver1) b=($ver2)

  if [ "${a[0]}" -gt "${b[0]}" ]; then return 1; fi
  if [ "${a[0]}" -lt "${b[0]}" ]; then return 2; fi
  if [ "${a[1]}" -gt "${b[1]}" ]; then return 1; fi
  if [ "${a[1]}" -lt "${b[1]}" ]; then return 2; fi
  if [ "${a[2]}" -gt "${b[2]}" ]; then return 1; fi
  if [ "${a[2]}" -lt "${b[2]}" ]; then return 2; fi
  return 0
}

add_file_info() {
  local f="$1"
  local h="NOT_FOUND"
  if [ -n "$f" ] && [ -f "$f" ]; then
    h=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    [ -z "$h" ] && h="HASH_ERROR"
    TARGET_FILES+=("$f")
  fi
  FILE_INFOS+=("$f (hash=$h)")
}

# ----------------------------
# Sendmail 점검
# 가이드:
#  - 사용 시: sendmail -d0 -bt 로 버전 확인 후 최신/패치 확인
#  - 미사용 시: systemctl list-units --type=service | grep sendmail 로 활성 여부 확인
# ----------------------------
check_sendmail() {
  command -v sendmail >/dev/null 2>&1 || return 0

  local listed active running ver cmp
  listed=$(systemctl list-units --type=service 2>/dev/null | grep -Ei "sendmail(\.service)?([[:space:]]|$)" | head -n 1)
  systemctl is-active sendmail >/dev/null 2>&1
  active=$?

  running=0
  if [ -n "$listed" ] || [ $active -eq 0 ]; then
    running=1
  fi

  if [ $running -eq 1 ]; then
    ver=$(sendmail -d0 -bt </dev/null 2>/dev/null | grep -i "Version" | awk '{print $2}' | head -n 1)
    add_file_info "/etc/mail/sendmail.cf"

    if [ -n "$ver" ]; then
      version_compare "$ver" "$SENDMAIL_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        FINDINGS+=("sendmail이 systemctl(list-units/is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${SENDMAIL_REQUIRED_VERSION}) 미만입니다.")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        FINDINGS+=("sendmail이 systemctl(list-units/is-active) 기준 실행 중이나 버전(${ver}) 형식 파싱이 불가하여 수동 확인이 필요합니다.")
      else
        FINDINGS+=("sendmail이 systemctl(list-units/is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${SENDMAIL_REQUIRED_VERSION}) 이상입니다.")
      fi
    else
      VULNERABLE=1
      FINDINGS+=("sendmail이 systemctl(list-units/is-active) 기준 실행 중이나 sendmail -d0 -bt로 버전 확인이 불가합니다.")
    fi
  fi
}

# ----------------------------
# Postfix 점검
# 가이드:
#  - 사용 시: postconf mail_version
#  - 미사용 시: ps -ef | grep postfix 로 PID 확인 후 종료(조치)
# ----------------------------
check_postfix() {
  command -v postconf >/dev/null 2>&1 || return 0

  local active ver cmp
  systemctl is-active postfix >/dev/null 2>&1
  active=$?

  if [ $active -eq 0 ]; then
    ver=$(postconf mail_version 2>/dev/null | cut -d= -f2 | xargs)
    add_file_info "/etc/postfix/main.cf"

    if [ -n "$ver" ]; then
      version_compare "$ver" "$POSTFIX_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        FINDINGS+=("postfix가 systemctl(is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${POSTFIX_REQUIRED_VERSION}) 미만입니다.")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        FINDINGS+=("postfix가 systemctl(is-active) 기준 실행 중이나 버전(${ver}) 형식 파싱이 불가하여 수동 확인이 필요합니다.")
      else
        FINDINGS+=("postfix가 systemctl(is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${POSTFIX_REQUIRED_VERSION}) 이상입니다.")
      fi
    else
      VULNERABLE=1
      FINDINGS+=("postfix가 systemctl(is-active) 기준 실행 중이나 postconf mail_version으로 버전 확인이 불가합니다.")
    fi
  else
    # 서비스는 inactive인데 프로세스가 남아있으면 비정상(가이드의 '미사용 시 PID 확인' 취지 반영)
    if ps -ef 2>/dev/null | grep -v grep | grep -qi postfix; then
      VULNERABLE=1
      FINDINGS+=("postfix가 systemctl(is-active) 기준 비활성이지만 ps 결과 postfix 프로세스가 잔존합니다.")
      add_file_info "/etc/postfix/main.cf"
    fi
  fi
}

# ----------------------------
# Exim 점검
# 가이드:
#  - 사용 시: systemctl list-units --type=service | grep exim 로 활성 확인 후 버전/패치
#  - 미사용 시: ps -ef | grep exim 로 PID 확인 후 종료(조치)
# ----------------------------
check_exim() {
  (command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1) || return 0

  local listed active running ver cmp
  listed=$(systemctl list-units --type=service 2>/dev/null | grep -Ei "exim4?(\.service)?([[:space:]]|$)" | head -n 1)

  systemctl is-active exim4 >/dev/null 2>&1
  active=$?
  running=0
  if [ -n "$listed" ] || [ $active -eq 0 ]; then
    running=1
  fi

  if [ $running -eq 1 ]; then
    ver=$(exim --version 2>/dev/null | head -1 | awk '{print $3}' | head -n 1)
    add_file_info "/etc/exim4/exim4.conf"

    if [ -n "$ver" ]; then
      version_compare "$ver" "$EXIM_REQUIRED_VERSION"
      cmp=$?
      if [ $cmp -eq 2 ]; then
        VULNERABLE=1
        FINDINGS+=("exim이 systemctl(list-units/is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${EXIM_REQUIRED_VERSION}) 미만입니다.")
      elif [ $cmp -eq 3 ]; then
        VULNERABLE=1
        FINDINGS+=("exim이 systemctl(list-units/is-active) 기준 실행 중이나 버전(${ver}) 형식 파싱이 불가하여 수동 확인이 필요합니다.")
      else
        FINDINGS+=("exim이 systemctl(list-units/is-active) 기준 실행 중이며 버전이 ${ver}로 요구 버전(${EXIM_REQUIRED_VERSION}) 이상입니다.")
      fi
    else
      VULNERABLE=1
      FINDINGS+=("exim이 systemctl(list-units/is-active) 기준 실행 중이나 exim --version으로 버전 확인이 불가합니다.")
    fi
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -qi exim; then
      VULNERABLE=1
      FINDINGS+=("exim이 systemctl(list-units/is-active) 기준 비활성이지만 ps 결과 exim 프로세스가 잔존합니다.")
      add_file_info "/etc/exim4/exim4.conf"
    fi
  fi
}

# 실제 점검 실행
check_sendmail
check_postfix
check_exim

# 결과 결정
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
fi

# target_file 문자열 구성
if [ ${#TARGET_FILES[@]} -gt 0 ]; then
  TARGET_FILE=$(printf "%s\n" "${TARGET_FILES[@]}" | awk '!seen[$0]++')
else
  TARGET_FILE="N/A"
fi

# findings 문자열 구성
if [ ${#FINDINGS[@]} -gt 0 ]; then
  FINDINGS_TEXT=$(printf "%s\n" "${FINDINGS[@]}")
else
  FINDINGS_TEXT="systemctl(list-units/is-active) 및 ps 점검 결과 실행 중인 메일 서비스가 확인되지 않았습니다."
fi

# 파일 해시 정보 문자열 구성
if [ ${#FILE_INFOS[@]} -gt 0 ]; then
  FILE_INFO_TEXT=$(printf "%s\n" "${FILE_INFOS[@]}")
else
  FILE_INFO_TEXT="N/A"
fi

# 3. 최종 출력(scan_history)
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='
(systemctl list-units --type=service 2>/dev/null | grep -Ei "sendmail(\.service)?([[:space:]]|$)" || true);
(systemctl is-active sendmail 2>/dev/null || true);
(command -v sendmail >/dev/null 2>&1 && sendmail -d0 -bt </dev/null 2>/dev/null | grep -i Version || true);

(systemctl is-active postfix 2>/dev/null || true);
(command -v postconf >/dev/null 2>&1 && postconf mail_version 2>/dev/null || true);
(ps -ef 2>/dev/null | grep -v grep | grep -i postfix || true);

(systemctl list-units --type=service 2>/dev/null | grep -Ei "exim4?(\.service)?([[:space:]]|$)" || true);
(systemctl is-active exim4 2>/dev/null || true);
(command -v exim >/dev/null 2>&1 && exim --version 2>/dev/null | head -1 || true);
(ps -ef 2>/dev/null | grep -v grep | grep -i exim || true);
'

REASON_LINE=""
DETAIL_CONTENT=""

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="systemctl(list-units/is-active)와 버전 확인 명령(sendmail -d0 -bt, postconf mail_version, exim --version) 결과, 메일 서비스가 비활성 상태이거나 실행 중인 메일 서비스 버전이 요구 버전 이상으로 확인되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(판정 근거)\n${FINDINGS_TEXT}\n(요구 버전)\nsendmail>=${SENDMAIL_REQUIRED_VERSION}, postfix>=${POSTFIX_REQUIRED_VERSION}, exim>=${EXIM_REQUIRED_VERSION}\n(대상 파일/해시)\n${FILE_INFO_TEXT}"
else
  REASON_LINE="systemctl(list-units/is-active)와 버전 확인 명령(sendmail -d0 -bt, postconf mail_version, exim --version) 결과, 실행 중인 메일 서비스의 버전이 요구 버전 미만이거나(또는) 프로세스 상태가 비정상(잔존)으로 확인되어 취약합니다."
  DETAIL_CONTENT="(판정 근거)\n${FINDINGS_TEXT}\n(요구 버전)\nsendmail>=${SENDMAIL_REQUIRED_VERSION}, postfix>=${POSTFIX_REQUIRED_VERSION}, exim>=${EXIM_REQUIRED_VERSION}\n(조치 방법)\n사용 중인 메일 서비스는 벤더 권고에 따라 최신 버전/보안 패치를 적용 후 재기동하여 버전을 재확인하고, 불필요한 서비스는 중지/비활성화(systemctl stop/disable)하며 잔존 프로세스는 정상 종료 후 필요 시 정리합니다.\n(대상 파일/해시)\n${FILE_INFO_TEXT}"
fi

escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF