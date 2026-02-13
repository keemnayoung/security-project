#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-11
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 사용자 shell 점검
# @Description : 로그인이 필요하지 않은 시스템 계정에 로그인 제한 쉘(/sbin/nologin) 부여
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-11"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"

CHECK_COMMAND="awk -F: '(\$1==\"daemon\"||\$1==\"bin\"||\$1==\"sys\"||\$1==\"adm\"||\$1==\"listen\"||\$1==\"nobody\"||\$1==\"nobody4\"||\$1==\"noaccess\"||\$1==\"diag\"||\$1==\"operator\"||\$1==\"games\"||\$1==\"gopher\"){print \$1\":\"\$7}' /etc/passwd 2>/dev/null"

SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

MODIFIED=0
FAIL_FLAG=0

# (추가) 허용 로그인 제한 쉘 목록 (/usr/sbin/nologin 고려)
ALLOWED_SHELLS=("/bin/false" "/sbin/nologin" "/usr/sbin/nologin")

is_allowed_shell() {
  local shell="$1"
  for s in "${ALLOWED_SHELLS[@]}"; do
    [ "$shell" = "$s" ] && return 0
  done
  return 1
}

# (추가) 조치에 사용할 쉘 자동 선택 (/sbin/nologin 우선, 없으면 /usr/sbin/nologin, 없으면 /bin/false)
pick_target_shell() {
  if [ -x /sbin/nologin ]; then
    echo "/sbin/nologin"
  elif [ -x /usr/sbin/nologin ]; then
    echo "/usr/sbin/nologin"
  else
    echo "/bin/false"
  fi
}

TARGET_LOGIN_SHELL="$(pick_target_shell)"

# 조치 수행(백업 없음)
if [ -f "$PASSWD_FILE" ]; then
  for acc in "${SYSTEM_ACCOUNTS[@]}"; do
    if id "$acc" >/dev/null 2>&1; then
      CURRENT_SHELL=$(awk -F: -v u="$acc" '$1==u {print $7}' "$PASSWD_FILE" 2>/dev/null | head -n 1)

      # (수정) 허용 쉘 목록에 없으면 취약으로 보고 조치
      # (CURRENT_SHELL이 비어도 허용 목록에 없으므로 조치 대상이 됨)
      if [ -n "$CURRENT_SHELL" ] || [ -z "$CURRENT_SHELL" ]; then
        if ! is_allowed_shell "$CURRENT_SHELL"; then
          if usermod -s "$TARGET_LOGIN_SHELL" "$acc" >/dev/null 2>&1; then
            MODIFIED=1
          else
            FAIL_FLAG=1
          fi
        fi
      fi
    fi
  done

  # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
  STILL_VULN_LIST=""
  AFTER_LIST=""

  for acc in "${SYSTEM_ACCOUNTS[@]}"; do
    if id "$acc" >/dev/null 2>&1; then
      SHELL_AFTER=$(awk -F: -v u="$acc" '$1==u {print $7}' "$PASSWD_FILE" 2>/dev/null | head -n 1)
      AFTER_LIST="${AFTER_LIST}${acc}:${SHELL_AFTER}
"

      # (수정) 허용 쉘 목록 기준으로 잔존 취약 판단
      if ! is_allowed_shell "$SHELL_AFTER"; then
        STILL_VULN_LIST="${STILL_VULN_LIST}${acc}:${SHELL_AFTER}
"
      fi
    fi
  done

  AFTER_LIST="$(echo "$AFTER_LIST" | sed '/^[[:space:]]*$/d')"
  STILL_VULN_LIST="$(echo "$STILL_VULN_LIST" | sed '/^[[:space:]]*$/d')"

  DETAIL_CONTENT="$AFTER_LIST"

  # 최종 판정
  if [ -z "$STILL_VULN_LIST" ] && [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="시스템 계정의 로그인 쉘이 로그인 제한 쉘(${TARGET_LOGIN_SHELL})로 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="모든 시스템 계정의 로그인 제한 설정이 이미 적용되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 일부 시스템 계정의 로그인 쉘이 제한 값으로 설정되지 않아 조치가 완료되지 않았습니다."
    if [ -n "$STILL_VULN_LIST" ]; then
      DETAIL_CONTENT="$STILL_VULN_LIST"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/passwd)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
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