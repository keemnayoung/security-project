#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-46 일반 사용자의 메일 서비스 실행 방지

# 기본 변수
ID="U-46"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 증적/대상 기본값
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='(command -v sendmail && grep -i "PrivacyOptions" /etc/mail/sendmail.cf); (command -v postsuper && stat -c "%a %n" /usr/sbin/postsuper); ( [ -f /usr/sbin/exiqgrep ] && stat -c "%a %n" /usr/sbin/exiqgrep )'

VULNERABLE=0
FOUND_ANY=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  if [ -z "$f" ]; then return; fi
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

# -----------------------------
# 1) Sendmail: sendmail.cf PrivacyOptions에 restrictqrun 존재 여부
# -----------------------------
if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1
  CF_FILE="/etc/mail/sendmail.cf"
  add_target_file "$CF_FILE"

  if [ ! -f "$CF_FILE" ]; then
    # 구성 파일이 없으면(설치/구성 미완) 판단 불가 → 취약 처리(운영 정책에 따라 조정 가능)
    VULNERABLE=1
    append_detail "[sendmail] sendmail command=FOUND, config_file=NOT_FOUND ($CF_FILE)"
  else
    # 주석 제외 PrivacyOptions 라인 수집
    PRIVACY_LINES="$(grep -i "PrivacyOptions" "$CF_FILE" 2>/dev/null | grep -v '^[[:space:]]*#')"

    if [ -z "$PRIVACY_LINES" ]; then
      VULNERABLE=1
      append_detail "[sendmail] config_file=FOUND, PrivacyOptions=NOT_SET (restrictqrun missing)"
    else
      # restrictqrun 포함 여부 확인
      if echo "$PRIVACY_LINES" | grep -qi "restrictqrun"; then
        append_detail "[sendmail] config_file=FOUND, PrivacyOptions=SET (restrictqrun=YES)"
      else
        VULNERABLE=1
        append_detail "[sendmail] config_file=FOUND, PrivacyOptions=SET (restrictqrun=NO) line=$(echo "$PRIVACY_LINES" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      fi
    fi
  fi
fi

# -----------------------------
# 2) Postfix: /usr/sbin/postsuper 의 others 실행권한(o+x) 여부 확인
# -----------------------------
if command -v postsuper >/dev/null 2>&1; then
  FOUND_ANY=1
  POSTSUPER="/usr/sbin/postsuper"
  add_target_file "$POSTSUPER"

  if [ ! -f "$POSTSUPER" ]; then
    # 바이너리가 없으면 점검 대상에서 제외(설치 흔적/경로 차이 가능)
    append_detail "[postfix] postsuper command=FOUND, binary=NOT_FOUND ($POSTSUPER)"
  else
    PERMS="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
    if ! echo "$PERMS" | grep -Eq '^[0-7]{3,4}$'; then
      VULNERABLE=1
      append_detail "[postfix] binary=FOUND, perm=UNKNOWN ($PERMS) -> manual check recommended"
    else
      # o+x 여부만 보되(요구사항), 4자리(특수권한)도 허용
      PERM_DEC=$((8#$PERMS))
      if [ $((PERM_DEC & 001)) -ne 0 ]; then
        VULNERABLE=1
        append_detail "[postfix] binary=FOUND, perm=$PERMS (others_exec=YES) -> vulnerable"
      else
        append_detail "[postfix] binary=FOUND, perm=$PERMS (others_exec=NO) -> safe"
      fi
    fi
  fi
fi

# -----------------------------
# 3) Exim: /usr/sbin/exiqgrep 의 others 실행권한(o+x) 여부 확인
# -----------------------------
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
  FOUND_ANY=1
  add_target_file "$EXIQGREP"

  PERMS="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if ! echo "$PERMS" | grep -Eq '^[0-7]{3,4}$'; then
    VULNERABLE=1
    append_detail "[exim] exiqgrep=FOUND, perm=UNKNOWN ($PERMS) -> manual check recommended"
  else
    PERM_DEC=$((8#$PERMS))
    if [ $((PERM_DEC & 001)) -ne 0 ]; then
      VULNERABLE=1
      append_detail "[exim] exiqgrep=FOUND, perm=$PERMS (others_exec=YES) -> vulnerable"
    else
      append_detail "[exim] exiqgrep=FOUND, perm=$PERMS (others_exec=NO) -> safe"
    fi
  fi
else
  # exiqgrep이 없으면 exim 관련 점검 대상이 없다고만 남김(설치 여부와 별개로 경로 차이 가능)
  append_detail "[exim] exiqgrep=NOT_FOUND ($EXIQGREP)"
fi

# -----------------------------
# 4) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않거나 점검 대상 파일이 없어 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="일반 사용자가 메일 서비스 관련 기능을 실행할 수 있거나, 실행 제한 설정(restrictqrun/others 실행권한)이 기준에 부합하지 않아 취약합니다. 비인가 메일 발송 또는 큐 제어가 발생할 수 있으므로 설정을 보완해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="일반 사용자의 메일 서비스 실행이 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정(비어있으면 대표 경로 표기)
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/mail/sendmail.cf, /usr/sbin/postsuper, /usr/sbin/exiqgrep"

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