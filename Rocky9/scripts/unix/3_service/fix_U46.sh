#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-46 일반 사용자의 메일 서비스 실행 방지

# 기본 변수
ID="U-46"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
[ -f /etc/mail/sendmail.cf ] && grep -inE "^[[:space:]]*O[[:space:]]+PrivacyOptions=" /etc/mail/sendmail.cf 2>/dev/null || echo "sendmail_cf_not_found_or_no_privacyoptions";
[ -f /usr/sbin/postsuper ] && stat -c "%U %G %a %n" /usr/sbin/postsuper 2>/dev/null || echo "postsuper_not_found";
[ -f /usr/sbin/exiqgrep ] && stat -c "%U %G %a %n" /usr/sbin/exiqgrep 2>/dev/null || echo "exiqgrep_not_found";
(command -v systemctl >/dev/null 2>&1 && systemctl is-active sendmail 2>/dev/null | head -n 1) || echo "systemctl_or_sendmail_service_unknown"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/mail/sendmail.cf, /usr/sbin/postsuper, /usr/sbin/exiqgrep"

ACTION_ERR_LOG=""

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 파일 수정(chmod/sed) 및 서비스 재시작이 실패할 수 있습니다."
fi

MODIFIED=0
FAIL_FLAG=0

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

# 권한 형식 검증(3~4자리 8진)
is_octal_perm() {
  echo "$1" | grep -Eq '^[0-7]{3,4}$'
}

# 기타 실행 비트(o+x) 존재 여부(001)
has_other_exec_bit() {
  local perm_raw="$1"
  is_octal_perm "$perm_raw" || return 0  # 형식 이상이면 "있다고 가정"하여 조치 실패로 유도하지 않음
  local dec=$((8#$perm_raw))
  [ $((dec & 001)) -ne 0 ]
}

# systemd sendmail restart(있을 때만)
restart_sendmail_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^sendmail\.service" || return 0
  systemctl restart sendmail 2>/dev/null || append_err "systemctl restart sendmail 실패"
}

########################################
# 1) Sendmail: PrivacyOptions에 restrictqrun 포함
########################################
CF_FILE="/etc/mail/sendmail.cf"
if command -v sendmail >/dev/null 2>&1 && [ -f "$CF_FILE" ]; then
  # PrivacyOptions 라인이 있고 restrictqrun이 없으면 추가, 라인이 없으면 신규 추가(보수적)
  if grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null | grep -qi 'restrictqrun'; then
    : # already ok
  else
    cp -a "$CF_FILE" "${CF_FILE}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "sendmail.cf 백업 실패"

    if grep -qE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null; then
      # 라인末에 ,restrictqrun 추가(중복 방지 위해 위에서 체크)
      sed -i '/^[[:space:]]*O[[:space:]]\+PrivacyOptions=/ s/$/,restrictqrun/' "$CF_FILE" 2>/dev/null \
        || append_err "sendmail.cf PrivacyOptions 수정 실패"
    else
      # 라인 자체가 없으면 추가
      echo "O PrivacyOptions=restrictqrun" >> "$CF_FILE" 2>/dev/null \
        || append_err "sendmail.cf PrivacyOptions 신규 추가 실패"
    fi

    MODIFIED=1
    restart_sendmail_if_exists
  fi
fi

########################################
# 2) Postfix: /usr/sbin/postsuper 기타 실행(o+x) 제거
########################################
POSTSUPER="/usr/sbin/postsuper"
if [ -f "$POSTSUPER" ]; then
  PERM="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
  if [ -z "$PERM" ] || ! is_octal_perm "$PERM"; then
    append_err "$POSTSUPER 권한 값을 확인할 수 없어 조치/검증이 불완전할 수 있습니다."
    FAIL_FLAG=1
  else
    if has_other_exec_bit "$PERM"; then
      chmod o-x "$POSTSUPER" 2>/dev/null || append_err "$POSTSUPER chmod o-x 실패"
      MODIFIED=1
    fi
  fi
fi

########################################
# 3) Exim: /usr/sbin/exiqgrep 기타 실행(o+x) 제거
########################################
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
  PERM="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if [ -z "$PERM" ] || ! is_octal_perm "$PERM"; then
    append_err "$EXIQGREP 권한 값을 확인할 수 없어 조치/검증이 불완전할 수 있습니다."
    FAIL_FLAG=1
  else
    if has_other_exec_bit "$PERM"; then
      chmod o-x "$EXIQGREP" 2>/dev/null || append_err "$EXIQGREP chmod o-x 실패"
      MODIFIED=1
    fi
  fi
fi

########################################
# 4) 조치 후/현재 상태 수집(현재 설정만 evidence에 포함)
########################################
# sendmail PrivacyOptions 현재값
if [ -f "$CF_FILE" ]; then
  PO_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null | head -n 1)"
  [ -z "$PO_LINE" ] && PO_LINE="PrivacyOptions_line_not_found"
  append_detail "sendmail_privacyoptions(after)=$PO_LINE"
  echo "$PO_LINE" | grep -qi 'restrictqrun' || FAIL_FLAG=1
else
  append_detail "sendmail_cf(after)=not_found"
fi

# postsuper/exiqgrep 권한 현재값
if [ -f "$POSTSUPER" ]; then
  STAT="$(stat -c '%U:%G %a %n' "$POSTSUPER" 2>/dev/null)"
  [ -z "$STAT" ] && STAT="stat_failed"
  append_detail "postsuper(after)=$STAT"
  P="$(echo "$STAT" | awk '{print $2}' 2>/dev/null)"
  if is_octal_perm "$P" && has_other_exec_bit "$P"; then
    FAIL_FLAG=1
  fi
else
  append_detail "postsuper(after)=not_found"
fi

if [ -f "$EXIQGREP" ]; then
  STAT="$(stat -c '%U:%G %a %n' "$EXIQGREP" 2>/dev/null)"
  [ -z "$STAT" ] && STAT="stat_failed"
  append_detail "exiqgrep(after)=$STAT"
  P="$(echo "$STAT" | awk '{print $2}' 2>/dev/null)"
  if is_octal_perm "$P" && has_other_exec_bit "$P"; then
    FAIL_FLAG=1
  fi
else
  append_detail "exiqgrep(after)=not_found"
fi

########################################
# 5) 최종 판정
########################################
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="일반 사용자의 메일 서비스 실행을 제한하도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="메일 서비스 실행 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 메일 서비스 실행 제한 설정이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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