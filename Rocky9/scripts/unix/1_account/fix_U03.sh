#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
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
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$CONF_FILE, $PAM_SYSTEM_AUTH, $PAM_PASSWORD_AUTH"

CHECK_COMMAND="( command -v authselect >/dev/null 2>&1 && authselect current 2>/dev/null ); ( command -v authselect >/dev/null 2>&1 && authselect check 2>/dev/null ); ( [ -f /etc/security/faillock.conf ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/security/faillock.conf | grep -iE '^(deny|unlock_time)[[:space:]]*=' | tail -n 10 ); ( [ -f /etc/pam.d/system-auth ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/system-auth | grep -E 'pam_faillock\\.so|pam_tally2\\.so|pam_tally\\.so' | tail -n 10 ); ( [ -f /etc/pam.d/password-auth ] && grep -inEv '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/password-auth | grep -E 'pam_faillock\\.so|pam_tally2\\.so|pam_tally\\.so' | tail -n 10 )"

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

# PAM 모듈 적용 여부 확인 함수
pam_has_lock_module() {
  local file="$1"
  [ -f "$file" ] || return 1
  grep -iEv '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null \
    | grep -Eq 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so'
}

# (추가) PAM에 pam_faillock 라인 삽입(deny/unlock_time은 faillock.conf에서 읽도록 PAM에는 값 미기재)
ensure_pam_faillock() {
  local file="$1"
  local stamp="$2"
  local tmp="${file}.tmp_${stamp}"

  [ -f "$file" ] || return 2

  # 이미 있으면 스킵
  if pam_has_lock_module "$file"; then
    return 0
  fi

  # 백업
  cp -p "$file" "${file}.bak_${stamp}" 2>/dev/null || return 3

  # 삽입 기준(보수적으로):
  # - preauth: 첫 번째 "auth ... pam_unix.so" 라인 앞
  # - authfail: 첫 번째 "auth ... pam_unix.so" 라인 뒤
  # - account: 첫 번째 "account ... pam_unix.so" 라인 앞(없으면 파일 끝)
  #
  # ※ PAM 인자(deny/unlock_time)는 넣지 않음(=faillock.conf 값 사용)

  awk '
  BEGIN {
    preauth_done=0; authfail_done=0; account_done=0;
    saw_auth_unix=0; saw_account_unix=0;
  }
  {
    line=$0;

    # auth pam_unix.so 감지
    if (line ~ /^[[:space:]]*auth[[:space:]].*pam_unix\.so/ && saw_auth_unix==0) {
      # preauth 삽입
      print "auth        required      pam_faillock.so preauth silent";
      preauth_done=1;
      print line;
      # authfail 삽입
      print "auth        [default=die] pam_faillock.so authfail";
      authfail_done=1;
      saw_auth_unix=1;
      next;
    }

    # account pam_unix.so 감지: 그 앞에 account 라인 삽입
    if (line ~ /^[[:space:]]*account[[:space:]].*pam_unix\.so/ && saw_account_unix==0) {
      print "account     required      pam_faillock.so";
      account_done=1;
      print line;
      saw_account_unix=1;
      next;
    }

    print line;
  }
  END {
    # auth pam_unix가 없으면 파일 끝에 auth 관련 라인 추가(최소 동작 목적)
    if (preauth_done==0) {
      print "auth        required      pam_faillock.so preauth silent";
    }
    if (authfail_done==0) {
      print "auth        [default=die] pam_faillock.so authfail";
    }
    # account pam_unix가 없으면 파일 끝에 account 라인 추가
    if (account_done==0) {
      print "account     required      pam_faillock.so";
    }
  }' "$file" > "$tmp" 2>/dev/null

  if [ ! -s "$tmp" ]; then
    rm -f "$tmp" 2>/dev/null
    return 4
  fi

  mv "$tmp" "$file" 2>/dev/null || return 5
  return 0
}

# -----------------------------
# 조치 전 상태 수집 + 백업
# -----------------------------
ACTION_LOG=""

DENY_BEFORE=""
UNLOCK_BEFORE=""
if [ -f "$CONF_FILE" ]; then
  DENY_BEFORE=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  UNLOCK_BEFORE=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)

  BACKUP_FILE="${CONF_FILE}.bak_${ACTION_DATE//[: ]/_}"
  if cp -p "$CONF_FILE" "$BACKUP_FILE" 2>/dev/null; then
    ACTION_LOG="backup_created=$BACKUP_FILE"
  else
    ACTION_LOG="backup_failed"
  fi
else
  ACTION_LOG="conf_file_not_found_before"
fi

# -----------------------------
# 조치 수행
# -----------------------------
AUTHSELECT_RESULT="not_installed"
AUTHSELECT_WITH_FAILLOCK="unknown"
AUTHSELECT_CONFIGURED="unknown"
PAM_DIRECT_FIX="not_attempted"

STAMP="${ACTION_DATE//[: ]/_}"

# authselect 상태 확인
if command -v authselect >/dev/null 2>&1; then
  authselect check >/dev/null 2>&1
  CK_RC=$?
  if [ $CK_RC -eq 0 ]; then
    AUTHSELECT_CONFIGURED="yes"
  else
    AUTHSELECT_CONFIGURED="no"
  fi

  if authselect current 2>/dev/null | grep -Eq 'with-faillock'; then
    AUTHSELECT_WITH_FAILLOCK="enabled"
  else
    AUTHSELECT_WITH_FAILLOCK="disabled_or_unknown"
  fi
fi

# 1) authselect가 구성되어 있으면 -> with-faillock 적용 시도
if command -v authselect >/dev/null 2>&1 && [ "$AUTHSELECT_CONFIGURED" = "yes" ]; then
  authselect enable-feature with-faillock >/dev/null 2>&1
  EN_RC=$?
  authselect apply-changes >/dev/null 2>&1
  AP_RC=$?

  if [ $EN_RC -eq 0 ] && [ $AP_RC -eq 0 ]; then
    AUTHSELECT_RESULT="success"
  else
    AUTHSELECT_RESULT="failed(enable_rc=$EN_RC,apply_rc=$AP_RC)"
  fi

  if authselect current 2>/dev/null | grep -Eq 'with-faillock'; then
    AUTHSELECT_WITH_FAILLOCK="enabled"
  else
    AUTHSELECT_WITH_FAILLOCK="disabled_or_unknown"
  fi
fi

# 2) authselect 미구성(또는 설치 안됨) -> PAM 직접 적용(필수 분기)
if [ "$AUTHSELECT_CONFIGURED" = "no" ] || [ "$AUTHSELECT_RESULT" != "success" ]; then
  # authselect가 없거나 미구성이라면 직접 적용을 시도
  # (단, authselect가 구성되어 있고 성공했으면 굳이 직접 수정하지 않음)
  if [ "$AUTHSELECT_CONFIGURED" = "no" ]; then
    PAM_DIRECT_FIX="attempted"
    # system-auth / password-auth 각각에 적용 시도
    ensure_pam_faillock "$PAM_SYSTEM_AUTH" "$STAMP"
    SYS_RC=$?
    ensure_pam_faillock "$PAM_PASSWORD_AUTH" "$STAMP"
    PWD_RC=$?

    # 로그에 결과 누적
    ACTION_LOG="${ACTION_LOG}\npam_direct_fix=attempted(system-auth_rc=$SYS_RC,password-auth_rc=$PWD_RC)"
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

# -----------------------------
# 조치 후 상태 수집
# -----------------------------
DENY_VAL=""
UNLOCK_VAL=""

if [ -f "$CONF_FILE" ]; then
  DENY_VAL=$(grep -iE '^[[:space:]]*deny[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
  UNLOCK_VAL=$(grep -iE '^[[:space:]]*unlock_time[[:space:]]*=' "$CONF_FILE" 2>/dev/null \
    | tail -n 1 | sed 's/#.*$//' | sed 's/[[:space:]]//g' | cut -d'=' -f2)
fi

# PAM 적용 여부 확인(점검 스크립트와 정합성)
PAM_MODULE_STATUS="not_applied"
PAM_SYSTEM_HAS="no"
PAM_PASSWORD_HAS="no"

if pam_has_lock_module "$PAM_SYSTEM_AUTH"; then
  PAM_SYSTEM_HAS="yes"
fi
if pam_has_lock_module "$PAM_PASSWORD_AUTH"; then
  PAM_PASSWORD_HAS="yes"
fi

if [ "$PAM_SYSTEM_HAS" = "yes" ] || [ "$PAM_PASSWORD_HAS" = "yes" ]; then
  PAM_MODULE_STATUS="applied"
fi

DETAIL_CONTENT="deny=$DENY_VAL
unlock_time=$UNLOCK_VAL
pam_module_status=$PAM_MODULE_STATUS
pam_system_auth_has_module=$PAM_SYSTEM_HAS
pam_password_auth_has_module=$PAM_PASSWORD_HAS
authselect_configured=$AUTHSELECT_CONFIGURED
authselect_with_faillock=$AUTHSELECT_WITH_FAILLOCK
authselect_result=$AUTHSELECT_RESULT
deny_before=$DENY_BEFORE
unlock_time_before=$UNLOCK_BEFORE
action_log=$ACTION_LOG"

# -----------------------------
# 최종 판정(점검 기준과 일치)
# - deny/unlock_time이 설정되고
# - PAM에 pam_faillock/pam_tally(2) 모듈이 실제 적용되어 있어야 성공
# -----------------------------
if [ -f "$CONF_FILE" ] && [ "$DENY_VAL" = "10" ] && [ "$UNLOCK_VAL" = "120" ] && [ "$PAM_MODULE_STATUS" = "applied" ]; then
  IS_SUCCESS=1
  REASON_LINE="계정 잠금 임계값(deny=10)과 잠금 해제 시간(unlock_time=120)이 설정되었고, PAM에 pam_faillock/pam_tally(2) 모듈이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
else
  IS_SUCCESS=0
  if [ ! -f "$CONF_FILE" ]; then
    REASON_LINE="조치 대상 파일(/etc/security/faillock.conf)이 존재하지 않아 조치가 완료되지 않았습니다."
  elif [ "$PAM_MODULE_STATUS" != "applied" ]; then
    REASON_LINE="faillock.conf 설정은 적용되었을 수 있으나 PAM에 pam_faillock/pam_tally(2) 모듈이 적용되어 있지 않아 실제 계정 잠금 정책이 동작하지 않을 수 있으므로 조치가 완료되지 않았습니다."
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