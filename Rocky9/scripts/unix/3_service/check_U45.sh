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


# 기본 변수
ID="U-45"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# ===== 기준 버전 (필요 시 수정) =====
SENDMAIL_REQUIRED_VERSION="8.18.2"
POSTFIX_REQUIRED_VERSION="3.10.7"
EXIM_REQUIRED_VERSION="4.99.1"
# ====================================

# 증적용 기본값
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='systemctl is-active sendmail postfix exim exim4; sendmail -d0 -bt; postconf mail_version; exim --version; rpm -q sendmail postfix exim exim4'

# 내부 변수
VULNERABLE=0
FOUND_ANY=0
DETAIL_LINES=""

# 버전에서 숫자(최소 x.y.z)만 뽑기
extract_ver() {
  # 예: "3.10.7" / "3.10.7-1.el9" / "version 8.18.2" -> "3.10.7" / "8.18.2"
  echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

# cur < req 이면 0(취약), cur >= req 이면 1(양호), 파싱 실패면 2
ver_check_ge() {
  local cur_raw="$1"
  local req_raw="$2"
  local cur req
  cur="$(extract_ver "$cur_raw")"
  req="$(extract_ver "$req_raw")"

  if [ -z "$cur" ] || [ -z "$req" ]; then
    return 2
  fi

  # sort -V로 버전 비교 (cur가 req보다 앞이면 취약)
  # cur < req  => first == cur (and cur != req)
  local first
  first="$(printf "%s\n%s\n" "$cur" "$req" | sort -V | head -n1)"

  if [ "$cur" = "$req" ]; then
    return 1
  elif [ "$first" = "$cur" ]; then
    return 0
  else
    return 1
  fi
}

append_detail() {
  # DETAIL_LINES에 한 줄 추가
  local line="$1"
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  if [ -z "$f" ]; then return; fi
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

# -----------------------------
# 1) Sendmail 점검
# -----------------------------
if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1
  SENDMAIL_ACTIVE="N"
  systemctl is-active --quiet sendmail 2>/dev/null && SENDMAIL_ACTIVE="Y"

  # 버전 확인 (가이드: sendmail -d0 -bt)
  SENDMAIL_VER_RAW="$(sendmail -d0 < /dev/null 2>/dev/null | grep -i "Version" | awk '{print $2}' | head -n1)"
  [ -z "$SENDMAIL_VER_RAW" ] && SENDMAIL_VER_RAW="unknown"

  # 패키지 정보(참고)
  SENDMAIL_RPM="$(rpm -q sendmail 2>/dev/null | head -n1)"
  [ -z "$SENDMAIL_RPM" ] && SENDMAIL_RPM="not_installed_or_unknown"

  if [ "$SENDMAIL_ACTIVE" = "Y" ]; then
    add_target_file "/etc/mail/sendmail.cf"

    ver_check_ge "$SENDMAIL_VER_RAW" "$SENDMAIL_REQUIRED_VERSION"
    rc=$?
    if [ $rc -eq 0 ]; then
      VULNERABLE=1
      append_detail "[sendmail] active=Y version=$SENDMAIL_VER_RAW required=$SENDMAIL_REQUIRED_VERSION result=LOW (rpm=$SENDMAIL_RPM)"
    elif [ $rc -eq 2 ]; then
      VULNERABLE=1
      append_detail "[sendmail] active=Y version=$SENDMAIL_VER_RAW required=$SENDMAIL_REQUIRED_VERSION result=UNKNOWN (rpm=$SENDMAIL_RPM)"
    else
      append_detail "[sendmail] active=Y version=$SENDMAIL_VER_RAW required=$SENDMAIL_REQUIRED_VERSION result=OK (rpm=$SENDMAIL_RPM)"
    fi
  else
    # 서비스는 비활성이나 프로세스가 잔존하면 취약
    if ps -ef 2>/dev/null | grep -v grep | grep -qi sendmail; then
      VULNERABLE=1
      append_detail "[sendmail] active=N process=REMAINS result=ABNORMAL"
      add_target_file "/etc/mail/sendmail.cf"
    else
      append_detail "[sendmail] active=N result=NOT_RUNNING (rpm=$SENDMAIL_RPM)"
    fi
  fi
fi

# -----------------------------
# 2) Postfix 점검
# -----------------------------
if command -v postconf >/dev/null 2>&1; then
  FOUND_ANY=1
  POSTFIX_ACTIVE="N"
  systemctl is-active --quiet postfix 2>/dev/null && POSTFIX_ACTIVE="Y"

  # 버전 확인 (가이드: postconf mail_version)
  POSTFIX_VER_RAW="$(postconf mail_version 2>/dev/null | cut -d= -f2 | xargs)"
  [ -z "$POSTFIX_VER_RAW" ] && POSTFIX_VER_RAW="unknown"

  POSTFIX_RPM="$(rpm -q postfix 2>/dev/null | head -n1)"
  [ -z "$POSTFIX_RPM" ] && POSTFIX_RPM="not_installed_or_unknown"

  if [ "$POSTFIX_ACTIVE" = "Y" ]; then
    add_target_file "/etc/postfix/main.cf"

    ver_check_ge "$POSTFIX_VER_RAW" "$POSTFIX_REQUIRED_VERSION"
    rc=$?
    if [ $rc -eq 0 ]; then
      VULNERABLE=1
      append_detail "[postfix] active=Y version=$POSTFIX_VER_RAW required=$POSTFIX_REQUIRED_VERSION result=LOW (rpm=$POSTFIX_RPM)"
    elif [ $rc -eq 2 ]; then
      VULNERABLE=1
      append_detail "[postfix] active=Y version=$POSTFIX_VER_RAW required=$POSTFIX_REQUIRED_VERSION result=UNKNOWN (rpm=$POSTFIX_RPM)"
    else
      append_detail "[postfix] active=Y version=$POSTFIX_VER_RAW required=$POSTFIX_REQUIRED_VERSION result=OK (rpm=$POSTFIX_RPM)"
    fi
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -qi postfix; then
      VULNERABLE=1
      append_detail "[postfix] active=N process=REMAINS result=ABNORMAL (rpm=$POSTFIX_RPM)"
      add_target_file "/etc/postfix/main.cf"
    else
      append_detail "[postfix] active=N result=NOT_RUNNING (rpm=$POSTFIX_RPM)"
    fi
  fi
fi

# -----------------------------
# 3) Exim 점검
# -----------------------------
# exim 바이너리는 exim/exim4 둘 다 고려
EXIM_CMD=""
command -v exim >/dev/null 2>&1 && EXIM_CMD="exim"
[ -z "$EXIM_CMD" ] && command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"

if [ -n "$EXIM_CMD" ]; then
  FOUND_ANY=1

  EXIM_ACTIVE="N"
  systemctl is-active --quiet exim 2>/dev/null && EXIM_ACTIVE="Y"
  systemctl is-active --quiet exim4 2>/dev/null && EXIM_ACTIVE="Y"

  # 버전 확인 (가이드: exim --version)
  EXIM_VER_RAW="$($EXIM_CMD --version 2>/dev/null | head -n1 | awk '{print $3}')"
  [ -z "$EXIM_VER_RAW" ] && EXIM_VER_RAW="unknown"

  EXIM_RPM="$(rpm -q exim exim4 2>/dev/null | head -n1)"
  [ -z "$EXIM_RPM" ] && EXIM_RPM="not_installed_or_unknown"

  if [ "$EXIM_ACTIVE" = "Y" ]; then
    # 배포판마다 설정 파일 경로가 다를 수 있어 대표 경로만 target_file에 포함
    add_target_file "/etc/exim/exim.conf"
    add_target_file "/etc/exim4/exim4.conf"

    ver_check_ge "$EXIM_VER_RAW" "$EXIM_REQUIRED_VERSION"
    rc=$?
    if [ $rc -eq 0 ]; then
      VULNERABLE=1
      append_detail "[exim] active=Y version=$EXIM_VER_RAW required=$EXIM_REQUIRED_VERSION result=LOW (cmd=$EXIM_CMD rpm=$EXIM_RPM)"
    elif [ $rc -eq 2 ]; then
      VULNERABLE=1
      append_detail "[exim] active=Y version=$EXIM_VER_RAW required=$EXIM_REQUIRED_VERSION result=UNKNOWN (cmd=$EXIM_CMD rpm=$EXIM_RPM)"
    else
      append_detail "[exim] active=Y version=$EXIM_VER_RAW required=$EXIM_REQUIRED_VERSION result=OK (cmd=$EXIM_CMD rpm=$EXIM_RPM)"
    fi
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -qi exim; then
      VULNERABLE=1
      append_detail "[exim] active=N process=REMAINS result=ABNORMAL (cmd=$EXIM_CMD rpm=$EXIM_RPM)"
      add_target_file "/etc/exim/exim.conf"
      add_target_file "/etc/exim4/exim4.conf"
    else
      append_detail "[exim] active=N result=NOT_RUNNING (cmd=$EXIM_CMD rpm=$EXIM_RPM)"
    fi
  fi
fi

# -----------------------------
# 4) 최종 판정/문구 정리 (U-15~U-16 톤)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않거나 실행되지 않아 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="메일 서비스가 실행 중이거나 프로세스 상태가 비정상이며, 버전이 기준에 미달하거나 확인할 수 없어 취약합니다. 사용 중인 메일 서비스는 최신 보안 패치를 적용하거나, 불필요 시 서비스 중지 및 비활성화를 수행해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="실행 중인 메일 서비스의 버전이 기준 이상으로 확인되거나, 서비스가 실행되지 않아 이 항목에 대한 보안 위협이 없습니다."
  fi
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/mail/sendmail.cf, /etc/postfix/main.cf, /etc/exim/exim.conf, /etc/exim4/exim4.conf"

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