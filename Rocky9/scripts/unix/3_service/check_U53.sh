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

# 기본 변수
ID="U-53"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='command -v vsftpd; command -v proftpd; systemctl is-active vsftpd proftpd; grep -nE "^(ftpd_banner|banner_file)" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*ServerIdent" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null'

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

add_target_file() {
  local f="$1"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

# -----------------------------
# 1) vsftpd 점검: ftpd_banner 또는 banner_file 설정 여부 확인
# -----------------------------
if command -v vsftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  VS_CONF_CAND=("/etc/vsftpd.conf" "/etc/vsftpd/vsftpd.conf")
  VS_FOUND_CONF="N"
  VS_BANNER_OK="N"

  for conf in "${VS_CONF_CAND[@]}"; do
    if [ -f "$conf" ]; then
      VS_FOUND_CONF="Y"
      add_target_file "$conf"

      # 주석 제외 후 ftpd_banner / banner_file 확인
      FT_LINE="$(grep -nE '^[[:space:]]*ftpd_banner[[:space:]]*=' "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
      BF_LINE="$(grep -nE '^[[:space:]]*banner_file[[:space:]]*=' "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"

      if [ -n "$FT_LINE" ] || [ -n "$BF_LINE" ]; then
        VS_BANNER_OK="Y"
        [ -n "$FT_LINE" ] && append_detail "[vsftpd] $conf ftpd_banner=SET | $FT_LINE"
        [ -n "$BF_LINE" ] && append_detail "[vsftpd] $conf banner_file=SET | $BF_LINE"
      else
        append_detail "[vsftpd] $conf ftpd_banner/banner_file=NOT_SET"
      fi
    fi
  done

  if [ "$VS_FOUND_CONF" = "N" ]; then
    # 바이너리는 있는데 설정 파일을 못 찾으면 확인 불가 -> 취약 처리(운영 정책상)
    VULNERABLE=1
    append_detail "[vsftpd] command=FOUND but config_file=NOT_FOUND -> banner exposure control cannot be verified"
  else
    if [ "$VS_BANNER_OK" = "N" ]; then
      VULNERABLE=1
      append_detail "[vsftpd] banner_setting=INSUFFICIENT (need ftpd_banner or banner_file)"
    else
      append_detail "[vsftpd] banner_setting=OK"
    fi
  fi

  # 서비스 실행 여부(참고용)
  if systemctl is-active --quiet vsftpd 2>/dev/null; then
    append_detail "[vsftpd] service_active=Y"
  else
    append_detail "[vsftpd] service_active=N"
  fi
fi

# -----------------------------
# 2) ProFTPD 점검: ServerIdent 설정 여부 확인(권고: off 또는 최소 정보)
# -----------------------------
if command -v proftpd >/dev/null 2>&1; then
  FOUND_ANY=1
  PF_CONF_CAND=("/etc/proftpd/proftpd.conf" "/etc/proftpd.conf")
  PF_FOUND_CONF="N"
  PF_IDENT_OK="N"

  for conf in "${PF_CONF_CAND[@]}"; do
    if [ -f "$conf" ]; then
      PF_FOUND_CONF="Y"
      add_target_file "$conf"

      # 주석 제외 ServerIdent 라인
      SI_LINE="$(grep -nE '^[[:space:]]*ServerIdent\b' "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
      if [ -n "$SI_LINE" ]; then
        PF_IDENT_OK="Y"
        append_detail "[proftpd] $conf ServerIdent=SET | $SI_LINE"

        # off면 강한 양호 신호(정보 노출 억제)
        echo "$SI_LINE" | grep -qiE '\bServerIdent[[:space:]]+off\b' && append_detail "[proftpd] ServerIdent=OFF (recommended)"
      else
        append_detail "[proftpd] $conf ServerIdent=NOT_SET"
      fi
    fi
  done

  if [ "$PF_FOUND_CONF" = "N" ]; then
    VULNERABLE=1
    append_detail "[proftpd] command=FOUND but config_file=NOT_FOUND -> banner exposure control cannot be verified"
  else
    if [ "$PF_IDENT_OK" = "N" ]; then
      VULNERABLE=1
      append_detail "[proftpd] ServerIdent=INSUFFICIENT (not set)"
    else
      append_detail "[proftpd] ServerIdent=OK"
    fi
  fi

  if systemctl is-active --quiet proftpd 2>/dev/null; then
    append_detail "[proftpd] service_active=Y"
  else
    append_detail "[proftpd] service_active=N"
  fi
fi

# -----------------------------
# 3) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="FTP 배너(식별 정보) 설정이 미흡하여 서비스 정보(제품/버전 등)가 노출될 수 있어 취약합니다. vsftpd는 ftpd_banner 또는 banner_file을 설정하고, ProFTPD는 ServerIdent를 off 또는 최소 정보로 설정하는 등 정보 노출을 제한해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="FTP 배너(식별 정보)가 제한되도록 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
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