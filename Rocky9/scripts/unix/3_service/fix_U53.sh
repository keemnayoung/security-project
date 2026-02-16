#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-53 FTP 서비스 정보 노출 제한

# 기본 변수
ID="U-53"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
( command -v vsftpd >/dev/null 2>&1 && echo "vsftpd_installed" ) || echo "vsftpd_not_installed";
( command -v proftpd >/dev/null 2>&1 && echo "proftpd_installed" ) || echo "proftpd_not_installed";
for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && echo "conf_exists:$f"; done
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"
ACTION_ERR_LOG=""

# 표준 배너(제품/버전 노출 금지)
SAFE_BANNER="Welcome to FTP service"
SAFE_BANNER_FILE="/etc/vsftpd/banner.txt"

add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE/N\/A/}${TARGET_FILE:+, }$1"; TARGET_FILE="${TARGET_FILE#, }"; }

backup_file(){
  local f="$1" b="${1}.bak_$(date +%Y%m%d_%H%M%S)"
  cp -a "$f" "$b" 2>/dev/null || return 1
  add_target "$b"
  return 0
}

restart_if_possible(){
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${svc}\.service[[:space:]]" || return 0
  systemctl restart "${svc}.service" >/dev/null 2>&1 || return 1
  return 0
}

set_or_append_kv(){ # $1=file $2=key $3=value
  local f="$1" k="$2" v="$3"
  if grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -qE "^[[:space:]]*${k}[[:space:]]*="; then
    sed -i -E "s|^[[:space:]]*${k}[[:space:]]*=.*$|${k}=${v}|g" "$f" 2>/dev/null || return 1
  else
    echo "${k}=${v}" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

set_serverident_off(){ # $1=file
  local f="$1"
  if grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE '^[[:space:]]*ServerIdent([[:space:]]|$)'; then
    sed -i -E 's|^[[:space:]]*ServerIdent[[:space:]]+.*$|ServerIdent off|gI' "$f" 2>/dev/null || return 1
  else
    echo "ServerIdent off" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

# 1) 권한 확인
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 FTP 서비스 정보 노출 제한 설정을 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
else
  FAIL=0
  MOD=0

  # 2) vsftpd 조치: banner_file을 표준 파일로 통일(또는 ftpd_banner로 통일)
  if command -v vsftpd >/dev/null 2>&1; then
    VS_CONF=""
    [ -f /etc/vsftpd.conf ] && VS_CONF="/etc/vsftpd.conf"
    [ -z "$VS_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VS_CONF="/etc/vsftpd/vsftpd.conf"

    if [ -z "$VS_CONF" ]; then
      FAIL=1
      add_detail "vsftpd(after)=installed_but_conf_not_found"
    else
      add_target "$VS_CONF"
      backup_file "$VS_CONF" || { FAIL=1; add_err "vsftpd 설정 파일 백업 실패: $VS_CONF"; }

      # 배너 파일 생성/고정
      mkdir -p "$(dirname "$SAFE_BANNER_FILE")" 2>/dev/null
      echo "$SAFE_BANNER" > "$SAFE_BANNER_FILE" 2>/dev/null || { FAIL=1; add_err "vsftpd 배너 파일 생성 실패: $SAFE_BANNER_FILE"; }
      add_target "$SAFE_BANNER_FILE"

      # banner_file 표준화 + ftpd_banner도 표준화(둘 중 하나만 있어도 되지만 혼선 방지 위해 둘 다 안전값)
      set_or_append_kv "$VS_CONF" "banner_file" "$SAFE_BANNER_FILE" || { FAIL=1; add_err "vsftpd banner_file 설정 실패: $VS_CONF"; }
      set_or_append_kv "$VS_CONF" "ftpd_banner" "$SAFE_BANNER" || { FAIL=1; add_err "vsftpd ftpd_banner 설정 실패: $VS_CONF"; }
      MOD=1

      restart_if_possible vsftpd || add_err "vsftpd 재시작 실패"

      # after 증적(현재 설정만)
      bf_line="$(grep -nEv '^[[:space:]]*#' "$VS_CONF" 2>/dev/null | grep -nE '^[[:space:]]*banner_file[[:space:]]*=' | head -n1)"
      fb_line="$(grep -nEv '^[[:space:]]*#' "$VS_CONF" 2>/dev/null | grep -nE '^[[:space:]]*ftpd_banner[[:space:]]*=' | head -n1)"
      btxt="$(head -n 1 "$SAFE_BANNER_FILE" 2>/dev/null | tr '\n' ' ')"
      add_detail "vsftpd_conf(after)=$VS_CONF"
      add_detail "vsftpd_banner_file(after)=${bf_line:-banner_file_not_found}"
      add_detail "vsftpd_ftpd_banner(after)=${fb_line:-ftpd_banner_not_found}"
      add_detail "vsftpd_banner_file_content(after)=${btxt:-empty}"
    fi
  else
    add_detail "vsftpd(after)=not_installed"
  fi

  # 3) proftpd 조치: ServerIdent off
  if command -v proftpd >/dev/null 2>&1; then
    PF_CONF=""
    [ -f /etc/proftpd/proftpd.conf ] && PF_CONF="/etc/proftpd/proftpd.conf"
    [ -z "$PF_CONF" ] && [ -f /etc/proftpd.conf ] && PF_CONF="/etc/proftpd.conf"

    if [ -z "$PF_CONF" ]; then
      FAIL=1
      add_detail "proftpd(after)=installed_but_conf_not_found"
    else
      add_target "$PF_CONF"
      backup_file "$PF_CONF" || { FAIL=1; add_err "proftpd 설정 파일 백업 실패: $PF_CONF"; }

      set_serverident_off "$PF_CONF" || { FAIL=1; add_err "proftpd ServerIdent off 설정 실패: $PF_CONF"; }
      MOD=1

      restart_if_possible proftpd || add_err "proftpd 재시작 실패"

      si_line="$(grep -nEv '^[[:space:]]*#' "$PF_CONF" 2>/dev/null | grep -niE '^[[:space:]]*ServerIdent([[:space:]]|$)' | head -n1)"
      add_detail "proftpd_conf(after)=$PF_CONF"
      add_detail "proftpd_ServerIdent(after)=${si_line:-ServerIdent_not_found}"
    fi
  else
    add_detail "proftpd(after)=not_installed"
  fi

  # 4) 최종 판정(조치 후 상태만 기반)
  if ! command -v vsftpd >/dev/null 2>&1 && ! command -v proftpd >/dev/null 2>&1; then
    IS_SUCCESS=1
    REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    if [ "$FAIL" -eq 0 ]; then
      IS_SUCCESS=1
      REASON_LINE="FTP 서비스의 접속 배너가 제품/버전 등 식별정보를 노출하지 않도록 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 일부 설정 파일/서비스 처리에 실패하여 조치가 완료되지 않았습니다."
    fi
  fi
fi

# 오류 로그는 detail 마지막에만 추가(이전 설정 값은 포함하지 않음)
[ -n "$ACTION_ERR_LOG" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}${ACTION_ERR_LOG}"

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
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