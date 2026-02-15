#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-54 암호화되지 않는 FTP 서비스 비활성화

set -u

# 기본 변수
ID="U-54"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*ftp([[:space:]]|$)" || echo "inetd_ftp_not_found_or_commented" );
( [ -d /etc/xinetd.d ] && grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null || echo "xinetd_disable_no_not_found" );
( command -v systemctl >/dev/null 2>&1 && (
    systemctl list-unit-files 2>/dev/null | grep -Ei "^(vsftpd|proftpd|pure-ftpd)\.service" || echo "ftp_units_not_found";
    systemctl is-active vsftpd proftpd pure-ftpd 2>/dev/null || true;
    systemctl is-enabled vsftpd proftpd pure-ftpd 2>/dev/null || true
  ) ) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/{ftp,proftp,vsftp}, systemd:{vsftpd,proftpd,pure-ftpd}.service"
ACTION_ERR_LOG=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }

backup_if_file(){
  local f="$1"
  [ -f "$f" ] || return 0
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || return 1
  return 0
}

# ---- 조치 시작 ----
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 암호화되지 않은 FTP 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
else
  # 1) inetd: /etc/inetd.conf ftp 라인 주석 처리
  if [ -f /etc/inetd.conf ]; then
    if grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*ftp([[:space:]]|$)'; then
      backup_if_file /etc/inetd.conf || add_err "/etc/inetd.conf 백업 실패"
      sed -i 's/^[[:space:]]*ftp/# ftp/' /etc/inetd.conf 2>/dev/null || add_err "/etc/inetd.conf ftp 주석 처리 실패"
      add_detail "[after][inetd] /etc/inetd.conf 에서 ftp 서비스 라인을 주석 처리했습니다."
      if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qi '^inetd\.service'; then
        systemctl restart inetd >/dev/null 2>&1 || add_err "inetd 재시작 실패"
      fi
    else
      add_detail "[after][inetd] /etc/inetd.conf 에서 ftp 서비스가 주석 처리(또는 미설정) 상태입니다."
    fi
  else
    add_detail "[after][inetd] /etc/inetd.conf 파일이 없어 inetd 기반 FTP 설정이 확인되지 않습니다."
  fi

  # 2) xinetd: /etc/xinetd.d/{ftp,proftp,vsftp} disable=yes 표준화
  if [ -d /etc/xinetd.d ]; then
    XCH=0
    for f in /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp; do
      [ -f "$f" ] || continue
      if grep -vi '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
        backup_if_file "$f" || add_err "$f 백업 실패"
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]\b/\1yes/' "$f" 2>/dev/null || add_err "$f disable=yes 변경 실패"
        add_detail "[after][xinetd] $f 에서 disable=yes 로 변경했습니다."
        XCH=1
      else
        add_detail "[after][xinetd] $f 에서 disable=no 설정이 없어 비활성화 상태로 판단됩니다."
      fi
    done
    if [ "$XCH" -eq 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qi '^xinetd\.service'; then
      systemctl restart xinetd >/dev/null 2>&1 || add_err "xinetd 재시작 실패"
    fi
  else
    add_detail "[after][xinetd] /etc/xinetd.d 디렉터리가 없어 xinetd 기반 FTP 설정이 확인되지 않습니다."
  fi

  # 3) systemd: FTP 데몬 stop/disable/mask (enabled까지 차단)
  if command -v systemctl >/dev/null 2>&1; then
    for s in vsftpd proftpd pure-ftpd; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
        systemctl stop "$s" >/dev/null 2>&1 || true
        systemctl disable "$s" >/dev/null 2>&1 || true
        systemctl mask "$s" >/dev/null 2>&1 || true
        add_detail "[after][systemd] ${s}.service 를 stop/disable/mask 처리했습니다."
      fi
    done
  else
    add_detail "[after][systemd] systemctl 을 사용할 수 없어 systemd 서비스 조치를 적용하지 못했습니다."
  fi

  # ---- 조치 후 검증(현재/after 상태만) ----
  FTP_ACTIVE=0

  # inetd
  if [ -f /etc/inetd.conf ] && grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*ftp([[:space:]]|$)'; then
    FTP_ACTIVE=1
    add_detail "[verify][inetd] /etc/inetd.conf 에서 ftp 서비스가 여전히 활성 상태입니다."
  else
    add_detail "[verify][inetd] /etc/inetd.conf 에서 ftp 서비스가 비활성(주석/미설정) 상태입니다."
  fi

  # xinetd
  if [ -d /etc/xinetd.d ] && grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b' /etc/xinetd.d/ftp /etc/xinetd.d/proftp /etc/xinetd.d/vsftp 2>/dev/null; then
    FTP_ACTIVE=1
    add_detail "[verify][xinetd] /etc/xinetd.d/* 에서 disable=no 설정이 확인되어 활성 상태입니다."
  else
    add_detail "[verify][xinetd] /etc/xinetd.d/* 에서 disable=no 설정이 없어 비활성 상태입니다."
  fi

  # systemd (active 또는 enabled면 취약)
  if command -v systemctl >/dev/null 2>&1; then
    for s in vsftpd proftpd pure-ftpd; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${s}\.service"; then
        systemctl is-active --quiet "$s" 2>/dev/null && { FTP_ACTIVE=1; add_detail "[verify][systemd] ${s}.service 가 active 상태입니다."; } \
                                                || add_detail "[verify][systemd] ${s}.service 는 active 상태가 아닙니다."
        systemctl is-enabled --quiet "$s" 2>/dev/null && { FTP_ACTIVE=1; add_detail "[verify][systemd] ${s}.service 가 enabled(자동시작) 상태입니다."; } \
                                                 || add_detail "[verify][systemd] ${s}.service 는 enabled 상태가 아닙니다."
      fi
    done
  fi

  if [ "$FTP_ACTIVE" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="암호화되지 않은 FTP 서비스가 비활성화되도록 설정이 적용되어 조치가 완료되었습니다."
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 FTP 서비스가 일부 경로에서 여전히 활성/자동시작 상태로 확인되어 조치가 완료되지 않았습니다."
  fi
fi

# detail에 에러 로그 병합(문장/after만)
[ -n "$ACTION_ERR_LOG" ] && add_detail "$ACTION_ERR_LOG"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# raw_evidence 구성(command/detail/target_file)  ※ before 미포함
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

# DB 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF