#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# @Criteria_Good : 암호화되지 않은 FTP 서비스가 비활성화된 경우
# @Criteria_Bad : 암호화되지 않은 FTP 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] 암호화되지 않는 FTP 서비스 비활성화

# 기본 변수
ID="U-54"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='grep -nE "^[[:space:]]*ftp\b" /etc/inetd.conf; grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no" /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null; systemctl list-units --type=service | grep -Ei "vsftpd|proftpd|(^|[^a-z])ftp([^a-z]|$)"; systemctl is-active vsftpd proftpd'

VULNERABLE=0
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
# 1) inetd.conf 내 ftp 활성화 여부
# -----------------------------
INETD_FILE="/etc/inetd.conf"
if [ -f "$INETD_FILE" ]; then
  add_target_file "$INETD_FILE"
  if grep -v '^[[:space:]]*#' "$INETD_FILE" 2>/dev/null | grep -qE '^[[:space:]]*ftp\b'; then
    VULNERABLE=1
    append_detail "[inetd] ftp entry=ENABLED in $INETD_FILE"
  else
    append_detail "[inetd] ftp entry=NOT_FOUND(or commented) in $INETD_FILE"
  fi
else
  append_detail "[inetd] $INETD_FILE=NOT_FOUND"
fi

# -----------------------------
# 2) xinetd.d 내 ftp 계열 서비스 활성화 여부(disable=no)
# -----------------------------
if [ -d "/etc/xinetd.d" ]; then
  for svc in ftp proftp vsftp; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      add_target_file "$f"
      if grep -vi '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
        VULNERABLE=1
        append_detail "[xinetd] $svc disable=no -> ENABLED | file=$f"
      else
        append_detail "[xinetd] $svc disable=no NOT_FOUND -> likely disabled | file=$f"
      fi
    else
      append_detail "[xinetd] $f=NOT_FOUND"
    fi
  done
else
  append_detail "[xinetd] /etc/xinetd.d=NOT_FOUND"
fi

# -----------------------------
# 3) systemd 서비스(vsftpd/proftpd/ftp) 활성화 여부
# -----------------------------
SYSTEMD_FTP_LIST="$(systemctl list-units --type=service 2>/dev/null | grep -Ei 'vsftpd|proftpd|(^|[^a-z])ftp([^a-z]|$)' || true)"
if [ -n "$SYSTEMD_FTP_LIST" ]; then
  VULNERABLE=1
  append_detail "[systemd] ftp-related service=FOUND | $(echo "$SYSTEMD_FTP_LIST" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
else
  append_detail "[systemd] ftp-related service=NOT_FOUND"
fi

# is-active도 참고(보다 직관적인 상태)
if systemctl is-active --quiet vsftpd 2>/dev/null; then
  VULNERABLE=1
  append_detail "[systemd] vsftpd_active=Y"
else
  append_detail "[systemd] vsftpd_active=N"
fi

if systemctl is-active --quiet proftpd 2>/dev/null; then
  VULNERABLE=1
  append_detail "[systemd] proftpd_active=Y"
else
  append_detail "[systemd] proftpd_active=N"
fi

# -----------------------------
# 4) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="암호화되지 않은 FTP 서비스가 활성화되어 있어 취약합니다. FTP는 통신 내용이 평문으로 전송될 수 있어 계정 정보 및 데이터가 노출될 위험이 있으므로 서비스를 중지 및 비활성화하고, 파일 전송은 SFTP/FTPS 등 암호화된 방식으로 전환해야 합니다."
else
  STATUS="PASS"
  REASON_LINE="암호화되지 않은 FTP 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/{ftp,proftp,vsftp}, systemd ftp-related units"

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