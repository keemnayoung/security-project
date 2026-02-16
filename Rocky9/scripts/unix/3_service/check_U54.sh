#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
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
CHECK_COMMAND='grep -nE "^[[:space:]]*ftp\b" /etc/inetd.conf 2>/dev/null; grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null; systemctl list-unit-files 2>/dev/null | grep -Ei "^(vsftpd|proftpd|pure-ftpd)\.service"; systemctl is-active vsftpd proftpd pure-ftpd 2>/dev/null; systemctl is-enabled vsftpd proftpd pure-ftpd 2>/dev/null'

VULNERABLE=0
DETAIL_LINES=""

add_detail() { [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_file()   { [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# 1) inetd: /etc/inetd.conf 에서 ftp 라인이 주석 없이 존재하면 취약
INETD="/etc/inetd.conf"
if [ -f "$INETD" ]; then
  add_file "$INETD"
  if grep -nEv '^[[:space:]]*#' "$INETD" 2>/dev/null | grep -nEq '^[[:space:]]*ftp\b'; then
    VULNERABLE=1
    add_detail "[inetd] $INETD 에서 ftp 서비스가 주석 없이 설정되어 활성화 상태입니다."
  else
    add_detail "[inetd] $INETD 에서 ftp 서비스가 주석 처리(또는 미설정)되어 비활성화 상태입니다."
  fi
else
  add_detail "[inetd] $INETD 파일이 없어 inetd 기반 FTP 설정이 확인되지 않습니다."
fi

# 2) xinetd: /etc/xinetd.d/* 에서 disable = no 이면 취약 (ftp/proftp/vsftp)
if [ -d "/etc/xinetd.d" ]; then
  for f in /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp; do
    if [ -f "$f" ]; then
      add_file "$f"
      if grep -vi '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
        VULNERABLE=1
        add_detail "[xinetd] $f 에서 disable=no 로 설정되어 FTP 서비스가 활성화 상태입니다."
      else
        add_detail "[xinetd] $f 에서 disable=no 설정이 없어(대개 disable=yes) 비활성화 상태입니다."
      fi
    fi
  done
else
  add_detail "[xinetd] /etc/xinetd.d 디렉터리가 없어 xinetd 기반 FTP 설정이 확인되지 않습니다."
fi

# 3) systemd: vsftpd/proftpd/pure-ftpd 가 active 또는 enabled면 취약
if command -v systemctl >/dev/null 2>&1; then
  for s in vsftpd proftpd pure-ftpd; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
      add_file "systemd:${s}.service"
      systemctl is-active --quiet "$s" 2>/dev/null && { VULNERABLE=1; add_detail "[systemd] ${s}.service 가 active(실행 중) 상태입니다."; } \
                                              || add_detail "[systemd] ${s}.service 는 active 상태가 아닙니다."
      systemctl is-enabled --quiet "$s" 2>/dev/null && { VULNERABLE=1; add_detail "[systemd] ${s}.service 가 enabled(부팅 시 자동 시작) 상태입니다."; } \
                                               || add_detail "[systemd] ${s}.service 는 enabled 상태가 아닙니다."
    fi
  done
else
  add_detail "[systemd] systemctl 명령을 사용할 수 없어 systemd 서비스 상태를 확인하지 못했습니다."
fi

# 최종 판정/문구(요청 톤)
if [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="점검 결과, 위 상세와 같이 암호화되지 않은 FTP 서비스가 설정/활성화되어 있어 취약합니다. 조치 방법: (1) /etc/inetd.conf의 ftp 라인을 주석 처리, (2) /etc/xinetd.d/ftp(해당 파일)에서 disable=yes로 변경 후 xinetd 재시작, (3) vsftpd/proftpd 등은 systemctl stop 및 systemctl disable로 비활성화하고 파일 전송은 SFTP/FTPS 등 암호화된 방식으로 전환하세요."
else
  STATUS="PASS"
  REASON_LINE="점검 결과, 위 상세와 같이 /etc/inetd.conf에서 ftp 서비스가 주석 처리(또는 미설정)되어 있고, /etc/xinetd.d/*에서도 disable=no 설정이 없으며, systemd 기반 FTP 데몬도 비활성화 상태로 확인되어 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="${DETAIL_LINES:-none}"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/{ftp,proftp,vsftp}, systemd:{vsftpd,proftpd,pure-ftpd}.service"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape(백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF