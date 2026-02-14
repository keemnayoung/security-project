#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-48 expn, vrfy 명령어 제한

# 기본 변수
ID="U-48"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='grep -nE "^[[:space:]]*O[[:space:]]+PrivacyOptions" /etc/mail/sendmail.cf; grep -nE "^[[:space:]]*disable_vrfy_command[[:space:]]*=" /etc/postfix/main.cf; grep -nE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" /etc/exim/exim.conf /etc/exim4/exim4.conf'

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
# 1) Sendmail: PrivacyOptions에 goaway 또는 (noexpn + novrfy) 확인
# -----------------------------
if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1
  CF_FILE="/etc/mail/sendmail.cf"
  add_target_file "$CF_FILE"

  if [ ! -f "$CF_FILE" ]; then
    VULNERABLE=1
    append_detail "[sendmail] command=FOUND sendmail.cf=NOT_FOUND -> expn/vrfy restriction status cannot be verified"
  else
    # 주석 제외 후 PrivacyOptions 라인 수집
    PRIVACY_LINES="$(grep -iE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$CF_FILE" 2>/dev/null | grep -v '^[[:space:]]*#')"
    if [ -z "$PRIVACY_LINES" ]; then
      VULNERABLE=1
      append_detail "[sendmail] PrivacyOptions=NOT_SET -> expn/vrfy restriction may be insufficient"
    else
      # 여러 라인이 있을 수 있어 모두 합쳐 판단(대/소문자 무시)
      PRIVACY_ALL="$(echo "$PRIVACY_LINES" | tr '\n' ' ' | tr '[:upper:]' '[:lower:]')"

      if echo "$PRIVACY_ALL" | grep -q "goaway"; then
        append_detail "[sendmail] PrivacyOptions includes 'goaway' -> safe"
      elif echo "$PRIVACY_ALL" | grep -q "noexpn" && echo "$PRIVACY_ALL" | grep -q "novrfy"; then
        append_detail "[sendmail] PrivacyOptions includes 'noexpn' and 'novrfy' -> safe"
      else
        VULNERABLE=1
        append_detail "[sendmail] PrivacyOptions missing required tokens (need goaway OR noexpn+novrfy) | lines=$(echo "$PRIVACY_LINES" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      fi
    fi
  fi
fi

# -----------------------------
# 2) Postfix: disable_vrfy_command = yes 확인 (expn은 기본 미지원이므로 vrfy 중심)
# -----------------------------
if command -v postfix >/dev/null 2>&1 || command -v postconf >/dev/null 2>&1; then
  FOUND_ANY=1
  MAIN_CF="/etc/postfix/main.cf"
  add_target_file "$MAIN_CF"

  if [ ! -f "$MAIN_CF" ]; then
    VULNERABLE=1
    append_detail "[postfix] command=FOUND main.cf=NOT_FOUND -> vrfy restriction status cannot be verified"
  else
    # 주석 제외 라인 기준으로 확인
    VRFY_LINE="$(grep -nE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' "$MAIN_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"

    if [ -z "$VRFY_LINE" ]; then
      VULNERABLE=1
      append_detail "[postfix] disable_vrfy_command=NOT_SET -> vulnerable"
    else
      # 값이 yes인지 확인
      if echo "$VRFY_LINE" | grep -qiE 'disable_vrfy_command[[:space:]]*=[[:space:]]*yes'; then
        append_detail "[postfix] disable_vrfy_command=yes -> safe | $VRFY_LINE"
      else
        VULNERABLE=1
        append_detail "[postfix] disable_vrfy_command is not 'yes' -> vulnerable | $VRFY_LINE"
      fi
    fi
  fi
fi

# -----------------------------
# 3) Exim: acl_smtp_vrfy / acl_smtp_expn 이 accept로 설정되어 있으면 취약 신호
# -----------------------------
EXIM_CMD=""
command -v exim >/dev/null 2>&1 && EXIM_CMD="exim"
[ -z "$EXIM_CMD" ] && command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"

if [ -n "$EXIM_CMD" ]; then
  FOUND_ANY=1
  CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
  FOUND_CONF="N"

  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF="Y"
      add_target_file "$conf"

      # 주석 제외 후 acl_smtp_(vrfy|expn) 라인 확인
      ACL_LINES="$(grep -nE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=' "$conf" 2>/dev/null | grep -v '^[[:space:]]*#')"

      if [ -z "$ACL_LINES" ]; then
        append_detail "[exim] $conf acl_smtp_vrfy/expn=NOT_SET (verify default policy if needed)"
      else
        # accept로 명시된 경우 취약 처리
        if echo "$ACL_LINES" | grep -qiE 'acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept'; then
          VULNERABLE=1
          append_detail "[exim] $conf acl_smtp_vrfy/expn=accept -> vulnerable | $(echo "$ACL_LINES" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
        else
          append_detail "[exim] $conf acl_smtp_vrfy/expn=SET (not accept) -> likely safe | $(echo "$ACL_LINES" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
        fi
      fi

      break
    fi
  done

  if [ "$FOUND_CONF" = "N" ]; then
    VULNERABLE=1
    append_detail "[exim] command=FOUND but config_file=NOT_FOUND -> expn/vrfy restriction status cannot be verified"
  fi
fi

# -----------------------------
# 4) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않아 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="expn/vrfy 명령어 제한 설정이 기준에 부합하지 않거나 확인할 수 없어 취약합니다. 메일 사용자 정보가 노출될 수 있으므로 Sendmail은 PrivacyOptions에 goaway 또는 noexpn/novrfy를 적용하고, Postfix는 disable_vrfy_command=yes로 설정하는 등 정책을 보완해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="expn/vrfy 명령어가 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
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