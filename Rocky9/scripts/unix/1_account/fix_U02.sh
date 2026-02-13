#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 패스워드 복잡성 설정
# @Description : 패스워드 복잡성 및 유효기간 설정을 KISA 권고 수준으로 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-02"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PW_CONF="/etc/security/pwquality.conf"
PWH_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"

TARGET_FILE="$PW_CONF
$PWH_CONF
$LOGIN_DEFS"

CHECK_COMMAND="( [ -f /etc/security/pwquality.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/pwquality.conf | grep -iE 'minlen|minclass|dcredit|ucredit|lcredit|ocredit|enforce_for_root' | tail -n 20 ); ( [ -f /etc/security/pwhistory.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/pwhistory.conf | grep -iE 'remember|file|enforce_for_root' | tail -n 20 ); ( [ -f /etc/login.defs ] && grep -inE '^[[:space:]]*PASS_(MAX|MIN)_DAYS[[:space:]]+' /etc/login.defs | tail -n 5 )"

# 파라미터 설정 함수(pwquality/pwhistory: '=', login.defs: 공백)
set_param() {
  local file=$1
  local param=$2
  local val=$3
  local sep=$4

  if [ ! -f "$file" ]; then
    return 1
  fi

  if grep -qE "^[[:space:]]*#?[[:space:]]*${param}([[:space:]]*${sep}|[[:space:]]+)" "$file" 2>/dev/null; then
    if [ "$sep" = "=" ]; then
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=.*|${param} = ${val}|I" "$file" 2>/dev/null
    else
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]+.*|${param}   ${val}|I" "$file" 2>/dev/null
    fi
  else
    if [ "$sep" = "=" ]; then
      echo "${param} = ${val}" >> "$file"
    else
      echo "${param}   ${val}" >> "$file"
    fi
  fi

  return 0
}

# token(단독 라인) 보장 함수 (enforce_for_root)
ensure_token_line() {
  local file="$1"
  local token="$2"
  [ -f "$file" ] || return 1
  if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -Eq "^[[:space:]]*${token}[[:space:]]*$"; then
    return 0
  fi
  echo "$token" >> "$file"
  return 0
}

# 조치 수행(백업 없음)

# 1) pwquality.conf (필수: minlen + credit 4종 + enforce_for_root)
if [ -f "$PW_CONF" ]; then
  set_param "$PW_CONF" "minlen" "8" "="
  set_param "$PW_CONF" "minclass" "3" "="
  set_param "$PW_CONF" "dcredit" "-1" "="
  set_param "$PW_CONF" "ucredit" "-1" "="
  set_param "$PW_CONF" "lcredit" "-1" "="
  set_param "$PW_CONF" "ocredit" "-1" "="
  ensure_token_line "$PW_CONF" "enforce_for_root"
fi

# 2) pwhistory.conf (필수: remember + file + enforce_for_root)
if [ -f "$PWH_CONF" ]; then
  set_param "$PWH_CONF" "remember" "4" "="
  set_param "$PWH_CONF" "file" "/etc/security/opasswd" "="
  ensure_token_line "$PWH_CONF" "enforce_for_root"
fi

# 3) login.defs (필수: PASS_MAX_DAYS + PASS_MIN_DAYS)
if [ -f "$LOGIN_DEFS" ]; then
  set_param "$LOGIN_DEFS" "PASS_MAX_DAYS" "90" "space"
  set_param "$LOGIN_DEFS" "PASS_MIN_DAYS" "1" "space"
fi

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
PW_MINLEN=""
PW_MINCLASS=""
PW_DCREDIT=""
PW_UCREDIT=""
PW_LCREDIT=""
PW_OCREDIT=""
PW_ENFORCE="N"

PWH_REMEMBER=""
PWH_FILE=""
PWH_ENFORCE="N"

PASS_MAX_DAYS=""
PASS_MIN_DAYS=""

if [ -f "$PW_CONF" ]; then
  PW_MINLEN=$(grep -iE '^[[:space:]]*minlen[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_MINCLASS=$(grep -iE '^[[:space:]]*minclass[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_DCREDIT=$(grep -iE '^[[:space:]]*dcredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_UCREDIT=$(grep -iE '^[[:space:]]*ucredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_LCREDIT=$(grep -iE '^[[:space:]]*lcredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PW_OCREDIT=$(grep -iE '^[[:space:]]*ocredit[[:space:]]*=' "$PW_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$PW_CONF" 2>/dev/null | grep -Eq '^[[:space:]]*enforce_for_root[[:space:]]*$' && PW_ENFORCE="Y"
fi

if [ -f "$PWH_CONF" ]; then
  PWH_REMEMBER=$(grep -iE '^[[:space:]]*remember[[:space:]]*=' "$PWH_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  PWH_FILE=$(grep -iE '^[[:space:]]*file[[:space:]]*=' "$PWH_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$PWH_CONF" 2>/dev/null | grep -Eq '^[[:space:]]*enforce_for_root[[:space:]]*$' && PWH_ENFORCE="Y"
fi

if [ -f "$LOGIN_DEFS" ]; then
  PASS_MAX_DAYS=$(grep -iE '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | tail -n 1 | awk '{print $2}')
  PASS_MIN_DAYS=$(grep -iE '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | tail -n 1 | awk '{print $2}')
fi

DETAIL_CONTENT="minlen=$PW_MINLEN
minclass=$PW_MINCLASS
dcredit=$PW_DCREDIT
ucredit=$PW_UCREDIT
lcredit=$PW_LCREDIT
ocredit=$PW_OCREDIT
pwquality_enforce_for_root=$PW_ENFORCE
remember=$PWH_REMEMBER
pwhistory_file=$PWH_FILE
pwhistory_enforce_for_root=$PWH_ENFORCE
pass_max_days=$PASS_MAX_DAYS
pass_min_days=$PASS_MIN_DAYS"

# 최종 판정(필수 기준)
if [ -f "$PW_CONF" ] && [ -f "$PWH_CONF" ] && [ -f "$LOGIN_DEFS" ] \
   && [ "$PW_MINLEN" = "8" ] \
   && [ "$PW_DCREDIT" = "-1" ] && [ "$PW_UCREDIT" = "-1" ] && [ "$PW_LCREDIT" = "-1" ] && [ "$PW_OCREDIT" = "-1" ] \
   && [ "$PW_ENFORCE" = "Y" ] \
   && [ -n "$PWH_REMEMBER" ] && [ "$PWH_REMEMBER" -ge 4 ] 2>/dev/null \
   && [ "$PWH_FILE" = "/etc/security/opasswd" ] \
   && [ "$PWH_ENFORCE" = "Y" ] \
   && [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -le 90 ] 2>/dev/null \
   && [ -n "$PASS_MIN_DAYS" ] && [ "$PASS_MIN_DAYS" -ge 1 ] 2>/dev/null; then
  IS_SUCCESS=1
  REASON_LINE="비밀번호 복잡성(minlen 및 credit 4종)과 root 강제(enforce_for_root), 재사용 제한(remember/file), 유효기간(PASS_MAX_DAYS/PASS_MIN_DAYS)이 가이드 기준으로 적용되어 조치가 완료되었습니다."
else
  IS_SUCCESS=0
  if [ ! -f "$PW_CONF" ] || [ ! -f "$PWH_CONF" ] || [ ! -f "$LOGIN_DEFS" ]; then
    REASON_LINE="조치 대상 파일 중 일부가 존재하지 않아 조치가 완료되지 않았습니다."
  else
    REASON_LINE="조치를 수행했으나 비밀번호 복잡성/재사용 제한/유효기간 설정 값이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
  fi
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