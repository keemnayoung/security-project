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

# 기본 변수
ID="U-54"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*ftp([[:space:]]|$)" || echo "inetd_ftp_not_found_or_commented" );
( [ -d /etc/xinetd.d ] && for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    bn="$(basename "$f")"
    echo "$bn" | grep -qiE "^(ftp|vsftp|vsftpd|proftp|proftpd)$" || continue
    echo "xinetd_conf:$f"
    grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1
  done ) || echo "xinetd_dir_not_found";
( command -v systemctl >/dev/null 2>&1 && (
    systemctl list-unit-files 2>/dev/null | grep -iE "^(vsftpd|proftpd|ftpd|ftp)\.service[[:space:]]" || echo "ftp_related_units_not_found";
    systemctl is-active vsftpd.service 2>/dev/null || true;
    systemctl is-active proftpd.service 2>/dev/null || true;
    systemctl is-active ftpd.service 2>/dev/null || true
  ) ) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"
ACTION_ERR_LOG=""

MODIFIED=0

append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
fi

restart_if_exists() {
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${svc}\.service[[:space:]]" || return 0
  systemctl restart "${svc}.service" >/dev/null 2>&1 || return 1
  return 0
}

disable_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
  systemctl mask "$unit" >/dev/null 2>&1 || true
  return 0
}

backup_file() {
  local f="$1"
  [ -f "$f" ] || return 1
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || return 1
  return 0
}

########################################
# 조치 프로세스
########################################
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 암호화되지 않는 FTP 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
else
  # 1) [inetd] /etc/inetd.conf에서 ftp 활성 라인 주석 처리
  if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*ftp([[:space:]]|$)"; then
      backup_file "/etc/inetd.conf" || append_err "/etc/inetd.conf 백업 실패"
      sed -i 's/^\([[:space:]]*ftp\)/#\1/g' /etc/inetd.conf 2>/dev/null || append_err "/etc/inetd.conf ftp 주석 처리 실패"
      MODIFIED=1
      append_detail "inetd_ftp(after)=commented"
      if ! restart_if_exists inetd; then
        append_err "inetd 재시작 실패"
      fi
    else
      append_detail "inetd_ftp(after)=not_active"
    fi
  else
    append_detail "inetd_conf(after)=not_found"
  fi

  # 2) [xinetd] /etc/xinetd.d/* 중 ftp 계열 disable=yes 설정
  XINETD_CHANGED=0
  if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
      [ -f "$conf" ] || continue
      bn="$(basename "$conf")"
      echo "$bn" | grep -qiE "^(ftp|vsftp|vsftpd|proftp|proftpd)$" || continue

      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        backup_file "$conf" || append_err "$conf 백업 실패"
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "$conf" 2>/dev/null \
          || append_err "$conf disable=yes 변경 실패"
        MODIFIED=1
        XINETD_CHANGED=1
        append_detail "xinetd_${bn}_disable(after)=yes"
      else
        AFTER_DISABLE="$(grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
        [ -z "$AFTER_DISABLE" ] && AFTER_DISABLE="disable_line_not_found"
        append_detail "xinetd_${bn}_disable(after)=$AFTER_DISABLE"
      fi
    done

    if [ "$XINETD_CHANGED" -eq 1 ]; then
      if ! restart_if_exists xinetd; then
        append_err "xinetd 재시작 실패"
      fi
    else
      append_detail "xinetd_ftp(after)=no_change_or_not_found"
    fi
  else
    append_detail "xinetd_dir(after)=not_found"
  fi

  # 3) [systemd] FTP 관련 서비스 stop/disable/mask
  if command -v systemctl >/dev/null 2>&1; then
    # 존재하는 unit만 대상으로 처리(오탐 방지)
    for unit in vsftpd.service proftpd.service ftpd.service ftp.service; do
      if systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]"; then
        disable_unit_if_exists "$unit"
        MODIFIED=1
        append_detail "systemd_${unit}(after)=disabled"
      fi
    done
  else
    append_detail "systemd(after)=not_available"
  fi

  ########################################
  # 검증(조치 후 상태만)
  ########################################
  FTP_ACTIVE=0

  # inetd ftp 활성 라인 존재 여부
  if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*ftp([[:space:]]|$)"; then
      FTP_ACTIVE=1
    fi
  fi

  # xinetd ftp 계열 disable=no 여부
  if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
      [ -f "$conf" ] || continue
      bn="$(basename "$conf")"
      echo "$bn" | grep -qiE "^(ftp|vsftp|vsftpd|proftp|proftpd)$" || continue
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        FTP_ACTIVE=1
      fi
    done
  fi

  # systemd 활성 여부
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active vsftpd.service >/dev/null 2>&1 && FTP_ACTIVE=1
    systemctl is-active proftpd.service >/dev/null 2>&1 && FTP_ACTIVE=1
    systemctl is-active ftpd.service >/dev/null 2>&1 && FTP_ACTIVE=1
    systemctl is-active ftp.service >/dev/null 2>&1 && FTP_ACTIVE=1
  fi

  if [ "$FTP_ACTIVE" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="암호화되지 않는 FTP 서비스가 비활성화되도록 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="암호화되지 않는 FTP 서비스가 이미 비활성화된 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 FTP 서비스가 일부 경로에서 여전히 활성화 상태로 확인되어 조치가 완료되지 않았습니다."
  fi
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF