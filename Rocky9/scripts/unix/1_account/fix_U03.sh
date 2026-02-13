#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-03
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 계정 잠금 임계값 설정
# @Description : 계정 탈취 공격 방지를 위해 로그인 실패 시 잠금 임계값 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-03"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CONF_FILE="/etc/security/faillock.conf"
TARGET_FILE="$CONF_FILE"

CHECK_COMMAND="( command -v authselect >/dev/null 2>&1 && authselect current 2>/dev/null ); ( [ -f /etc/security/faillock.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/faillock.conf | grep -iE '^(deny|unlock_time)[[:space:]]*=' | tail -n 10 )"

# 파라미터 설정 함수
set_param() {
  local file=$1
  local param=$2
  local val=$3

  if [ ! -f "$file" ]; then
    return 1
  fi

  if grep -qiE "^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=" "$file" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*${param}[[:space:]]*=.*|${param} = ${val}|I" "$file" 2>/dev/null
  else
    echo "${param} = ${val}" >> "$file"
  fi
  return 0
}

# (필수 추가) 조치 전 상태 수집 + 백업 + authselect 적용 결과 기록
ACTION_LOG=""

# 조치 전 값(없으면 빈 값)
DENY_BEFORE=""
UNLOCK_BEFORE=""
if [ -f "$CONF_FILE" ]; then
  DENY_BEFORE=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/[[:space:]]//g' | sed 's/#.*$//' | cut -d'=' -f2)
  UNLOCK_BEFORE=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/[[:space:]]//g' | sed 's/#.*$//' | cut -d'=' -f2)

  # 백업(필수)
  BACKUP_FILE="${CONF_FILE}.bak_${ACTION_DATE//[: ]/_}"
  if cp -p "$CONF_FILE" "$BACKUP_FILE" 2>/dev/null; then
    ACTION_LOG="backup_created=$BACKUP_FILE"
  else
    ACTION_LOG="backup_failed"
  fi
else
  ACTION_LOG="conf_file_not_found_before"
fi

AUTHSELECT_RESULT="not_installed"

# 조치 수행
# Rocky/RHEL 9 계열(authselect) 대응 + (필수) 성공/실패 확인
if command -v authselect >/dev/null 2>&1; then
  authselect enable-feature with-faillock >/dev/null 2>&1
  EN_RC=$?
  authselect apply-changes >/dev/null 2>&1
  AP_RC=$?

  if [ $EN_RC -eq 0 ] && [ $AP_RC -eq 0 ]; then
    AUTHSELECT_RESULT="success"
  else
    AUTHSELECT_RESULT="failed(enable_rc=$EN_RC,apply_rc=$AP_RC)"
  fi
fi

# 설정 파일 준비
if [ ! -f "$CONF_FILE" ]; then
  mkdir -p /etc/security 2>/dev/null
  touch "$CONF_FILE" 2>/dev/null
fi

if [ -f "$CONF_FILE" ]; then
  set_param "$CONF_FILE" "deny" "10"
  set_param "$CONF_FILE" "unlock_time" "120"
fi

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
DENY_VAL=""
UNLOCK_VAL=""

if [ -f "$CONF_FILE" ]; then
  DENY_VAL=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/[[:space:]]//g' | sed 's/#.*$//' | cut -d'=' -f2)
  UNLOCK_VAL=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/[[:space:]]//g' | sed 's/#.*$//' | cut -d'=' -f2)
fi

DETAIL_CONTENT="deny=$DENY_VAL
unlock_time=$UNLOCK_VAL
authselect_result=$AUTHSELECT_RESULT
deny_before=$DENY_BEFORE
unlock_time_before=$UNLOCK_BEFORE
action_log=$ACTION_LOG"

# 최종 판정
if [ -f "$CONF_FILE" ] && [ "$DENY_VAL" = "10" ] && [ "$UNLOCK_VAL" = "120" ]; then
  IS_SUCCESS=1
  REASON_LINE="계정 잠금 임계값이 10회로 설정되고 잠금 해제 시간이 120초로 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
else
  IS_SUCCESS=0
  if [ ! -f "$CONF_FILE" ]; then
    REASON_LINE="조치 대상 파일(/etc/security/faillock.conf)이 존재하지 않아 조치가 완료되지 않았습니다."
  else
    REASON_LINE="조치를 수행했으나 계정 잠금 임계값 또는 잠금 해제 시간 설정 값이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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