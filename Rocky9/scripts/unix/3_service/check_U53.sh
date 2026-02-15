#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Criteria_Good : FTP 접속 배너에 노출되는 정보가 없는 경우
# @Criteria_Bad : FTP 접속 배너에 노출되는 정보가 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-53 FTP 서비스 정보 노출 제한

set -u

# 기본 변수
ID="U-53"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='command -v vsftpd; command -v proftpd; systemctl is-active vsftpd proftpd; egrep -n "^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; egrep -n "^[[:space:]]*ServerIdent\\b" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null'

FOUND_ANY=0
VULN=0
DETAIL_LINES=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# 배너에 제품/버전 식별정보가 포함된 것으로 간주할 키워드/패턴(보수적)
is_leaky_banner() {
  local s="${1:-}"
  echo "$s" | grep -qiE '(vsftpd|proftpd|version|[0-9]+\.[0-9]+)'
}

# key=value 형태에서 value만 추출(따옴표 제거)
get_kv_value() {
  echo "$1" | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"$//'
}

# -----------------------------
# 1) vsftpd 점검
# -----------------------------
if command -v vsftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  VS_OK=0
  VS_CONF_FOUND=0

  for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f "$conf" ] || continue
    VS_CONF_FOUND=1
    add_target "$conf"

    ft_line="$(grep -nE '^[[:space:]]*ftpd_banner[[:space:]]*=' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"
    bf_line="$(grep -nE '^[[:space:]]*banner_file[[:space:]]*=' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"

    if [ -n "$ft_line" ]; then
      val="$(get_kv_value "$ft_line")"
      add_detail "[vsftpd] $conf | $ft_line"
      if is_leaky_banner "$val"; then
        VULN=1
        add_detail "[vsftpd] banner_value=LEAKY(제품/버전 추정 문자열 포함)"
      else
        VS_OK=1
        add_detail "[vsftpd] banner_value=OK(식별정보 노출 징후 없음)"
      fi
    fi

    if [ -n "$bf_line" ]; then
      bf="$(get_kv_value "$bf_line")"
      add_detail "[vsftpd] $conf | $bf_line"
      if [ -n "$bf" ] && [ -f "$bf" ]; then
        add_target "$bf"
        btxt="$(head -n 3 "$bf" 2>/dev/null | tr '\n' ' ')"
        add_detail "[vsftpd] banner_file_content(head)=${btxt:-empty}"
        if is_leaky_banner "$btxt"; then
          VULN=1
          add_detail "[vsftpd] banner_file_content=LEAKY(제품/버전 추정 문자열 포함)"
        else
          VS_OK=1
          add_detail "[vsftpd] banner_file_content=OK(식별정보 노출 징후 없음)"
        fi
      else
        VULN=1
        add_detail "[vsftpd] banner_file=NOT_FOUND(파일 미존재/경로 확인 필요)"
      fi
    fi

    # 둘 다 없으면 취약
    if [ -z "$ft_line" ] && [ -z "$bf_line" ]; then
      VULN=1
      add_detail "[vsftpd] $conf | ftpd_banner/banner_file=NOT_SET"
    fi
  done

  if [ $VS_CONF_FOUND -eq 0 ]; then
    VULN=1
    add_detail "[vsftpd] command=FOUND but config_file=NOT_FOUND"
  fi

  if systemctl is-active --quiet vsftpd 2>/dev/null; then
    add_detail "[vsftpd] service_active=Y"
  else
    add_detail "[vsftpd] service_active=N"
  fi
fi

# -----------------------------
# 2) ProFTPD 점검
# -----------------------------
if command -v proftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  PF_CONF_FOUND=0
  PF_OK=0

  for conf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
    [ -f "$conf" ] || continue
    PF_CONF_FOUND=1
    add_target "$conf"

    si_line="$(grep -nE '^[[:space:]]*ServerIdent\b' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*#' | head -n1)"
    if [ -z "$si_line" ]; then
      VULN=1
      add_detail "[proftpd] $conf | ServerIdent=NOT_SET"
      continue
    fi

    add_detail "[proftpd] $conf | $si_line"

    # off면 최우선 양호
    if echo "$si_line" | grep -qiE '\bServerIdent[[:space:]]+off\b'; then
      PF_OK=1
      add_detail "[proftpd] ServerIdent=OFF(recommended)"
      continue
    fi

    # on "<배너>" 또는 on 형태: 배너 문자열 검사
    if echo "$si_line" | grep -qiE '\bServerIdent[[:space:]]+on\b'; then
      # 따옴표 안 문구를 우선 추출, 없으면 라인 전체로 검사
      banner="$(echo "$si_line" | sed -nE 's/.*ServerIdent[[:space:]]+on[[:space:]]+"([^"]*)".*/\1/p')"
      [ -z "$banner" ] && banner="$si_line"
      if is_leaky_banner "$banner"; then
        VULN=1
        add_detail "[proftpd] ServerIdent_value=LEAKY(제품/버전 추정 문자열 포함)"
      else
        PF_OK=1
        add_detail "[proftpd] ServerIdent_value=OK(식별정보 노출 징후 없음)"
      fi
    else
      # 예상 외 설정(보수적으로 취약)
      VULN=1
      add_detail "[proftpd] ServerIdent=UNKNOWN_FORMAT(검증 필요)"
    fi
  done

  if [ $PF_CONF_FOUND -eq 0 ]; then
    VULN=1
    add_detail "[proftpd] command=FOUND but config_file=NOT_FOUND"
  fi

  if systemctl is-active --quiet proftpd 2>/dev/null; then
    add_detail "[proftpd] service_active=Y"
  else
    add_detail "[proftpd] service_active=N"
  fi
fi

# -----------------------------
# 3) 최종 판정/문구(요청 톤 반영)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULN -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="(vsftpd/proftpd) 설정 파일에서 FTP 접속 배너가 미설정이거나, 배너 문자열/파일 내용에 제품·버전 등 식별정보가 포함될 수 있도록 설정되어 있어 취약합니다. 조치: vsftpd는 ftpd_banner 또는 banner_file로 일반 안내 문구만 설정하고, ProFTPD는 ServerIdent off 또는 ServerIdent on \"일반 문구\"로 설정 후 서비스를 재시작하세요."
  else
    STATUS="PASS"
    REASON_LINE="(vsftpd/proftpd) 설정 파일에서 FTP 접속 배너가 식별정보(제품/버전) 노출 없이 제한되도록 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi
  DETAIL_CONTENT="${DETAIL_LINES:-none}"
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf"

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