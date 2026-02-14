#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
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
for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
  [ -f "$f" ] && echo "conf_exists:$f"
done
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
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
fi

restart_if_exists() {
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${svc}\.service[[:space:]]" || return 0
  systemctl restart "${svc}.service" >/dev/null 2>&1 || return 1
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
  REASON_LINE="root 권한이 아니어서 FTP 서비스 정보 노출 제한 설정을 적용할 수 없어 조치를 중단합니다."
else
  # 1) vsftpd: ftpd_banner 설정
  VSFTPD_CONF=""
  if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
  elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
  fi

  if command -v vsftpd >/dev/null 2>&1 && [ -n "$VSFTPD_CONF" ]; then
    TARGET_FILE="$VSFTPD_CONF"

    # ftpd_banner가 없으면 추가, 있으면 안전 치환(주석 제외)
    if ! grep -nEv '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -qE '^[[:space:]]*ftpd_banner[[:space:]]*='; then
      backup_file "$VSFTPD_CONF" || append_err "$VSFTPD_CONF 백업 실패"
      echo "ftpd_banner=Welcome to FTP Service" >> "$VSFTPD_CONF" 2>/dev/null || append_err "$VSFTPD_CONF ftpd_banner 추가 실패"
      MODIFIED=1
    else
      # 값이 과도하게 노출되는 경우를 고려해 표준 배너로 치환(주석 제외 라인만)
      if grep -nEv '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -qE '^[[:space:]]*ftpd_banner[[:space:]]*=[[:space:]]*.+$'; then
        backup_file "$VSFTPD_CONF" || append_err "$VSFTPD_CONF 백업 실패"
        sed -i -E 's|^[[:space:]]*ftpd_banner[[:space:]]*=.*$|ftpd_banner=Welcome to FTP Service|g' "$VSFTPD_CONF" 2>/dev/null || append_err "$VSFTPD_CONF ftpd_banner 치환 실패"
        MODIFIED=1
      fi
    fi

    # 재시작
    if ! restart_if_exists vsftpd; then
      append_err "vsftpd 재시작 실패"
    fi

    # after 근거(현재 설정만)
    VS_BANNER_LINE="$(grep -nEv '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -nE '^[[:space:]]*ftpd_banner[[:space:]]*=' | head -n 1)"
    [ -z "$VS_BANNER_LINE" ] && VS_BANNER_LINE="ftpd_banner_not_found"
    append_detail "vsftpd_conf(after)=$VSFTPD_CONF"
    append_detail "vsftpd_ftpd_banner(after)=$VS_BANNER_LINE"
  else
    append_detail "vsftpd(after)=not_installed_or_conf_not_found"
  fi

  # 2) proftpd: ServerIdent off 설정
  PROFTPD_CONF=""
  if [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
  elif [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
  fi

  if command -v proftpd >/dev/null 2>&1 && [ -n "$PROFTPD_CONF" ]; then
    # TARGET_FILE는 대표 1개만 담되, detail에 각 파일 기록
    [ "$TARGET_FILE" = "N/A" ] && TARGET_FILE="$PROFTPD_CONF"

    # ServerIdent 설정: 없으면 추가, 있으면 off로 안전 치환(주석 제외)
    if ! grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*ServerIdent([[:space:]]|$)'; then
      backup_file "$PROFTPD_CONF" || append_err "$PROFTPD_CONF 백업 실패"
      echo "ServerIdent off" >> "$PROFTPD_CONF" 2>/dev/null || append_err "$PROFTPD_CONF ServerIdent 추가 실패"
      MODIFIED=1
    else
      if ! grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*ServerIdent[[:space:]]+off([[:space:]]|$)'; then
        backup_file "$PROFTPD_CONF" || append_err "$PROFTPD_CONF 백업 실패"
        sed -i -E 's|^[[:space:]]*ServerIdent[[:space:]]+.*$|ServerIdent off|gI' "$PROFTPD_CONF" 2>/dev/null || append_err "$PROFTPD_CONF ServerIdent off 치환 실패"
        MODIFIED=1
      fi
    fi

    if ! restart_if_exists proftpd; then
      append_err "proftpd 재시작 실패"
    fi

    PRO_IDENT_LINE="$(grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -niE '^[[:space:]]*ServerIdent([[:space:]]|$)' | head -n 1)"
    [ -z "$PRO_IDENT_LINE" ] && PRO_IDENT_LINE="ServerIdent_not_found"
    append_detail "proftpd_conf(after)=$PROFTPD_CONF"
    append_detail "proftpd_ServerIdent(after)=$PRO_IDENT_LINE"
  else
    append_detail "proftpd(after)=not_installed_or_conf_not_found"
  fi

  ########################################
  # 최종 검증(조치 후 상태만)
  ########################################
  FAIL_FLAG=0

  # vsftpd 설치+conf 존재 시 ftpd_banner 존재 여부 확인
  if command -v vsftpd >/dev/null 2>&1 && [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
    if ! grep -nEv '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -qE '^[[:space:]]*ftpd_banner[[:space:]]*='; then
      FAIL_FLAG=1
      append_detail "vsftpd_verify(after)=ftpd_banner_missing"
    else
      append_detail "vsftpd_verify(after)=ok"
    fi
  fi

  # proftpd 설치+conf 존재 시 ServerIdent off 확인
  if command -v proftpd >/dev/null 2>&1 && [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
    if ! grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*ServerIdent[[:space:]]+off([[:space:]]|$)'; then
      FAIL_FLAG=1
      append_detail "proftpd_verify(after)=ServerIdent_not_off"
    else
      append_detail "proftpd_verify(after)=ok"
    fi
  fi

  # 둘 다 미설치면(또는 설정 파일 없음) → 조치 대상 없음으로 성공 처리
  if ! command -v vsftpd >/dev/null 2>&1 && ! command -v proftpd >/dev/null 2>&1; then
    IS_SUCCESS=1
    REASON_LINE="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    if [ "$FAIL_FLAG" -eq 0 ]; then
      IS_SUCCESS=1
      if [ "$MODIFIED" -eq 1 ]; then
        REASON_LINE="FTP 서비스의 배너/식별 정보 노출이 제한되도록 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="FTP 서비스의 정보 노출 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 FTP 서비스 정보 노출 제한 설정이 일부 구성에서 기준을 충족하지 못해 조치가 완료되지 않았습니다."
    fi
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