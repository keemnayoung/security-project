#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-03
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 계정 잠금 임계값 설정
# @Description : 계정 탈취 공격(Brute Force 등) 방지를 위한 잠금 임계값 설정 여부 점검
# @Criteria_Good : 계정 잠금 임계값이 10회 이하로 설정된 경우
# @Criteria_Bad : 계정 잠금 임계값이 설정되지 않았거나 10회를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-03"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/security/faillock.conf"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

# 점검 명령(증적용)
CHECK_COMMAND="faillock.conf(deny/unlock_time), PAM(system-auth/password-auth)에서 pam_faillock/pam_tally(2) 적용 및 deny 값 확인, authselect with-faillock 여부 확인"

REASON_LINE=""
DETAIL_CONTENT=""

# 수집 변수
DENY_FROM_FAILLOCK_CONF=""
UNLOCK_FROM_FAILLOCK_CONF=""
DENY_FROM_PAM=""
UNLOCK_FROM_PAM=""
PAM_MODULE_STATUS="not_checked"
AUTHSELECT_WITH_FAILLOCK="unknown"

EFFECTIVE_DENY=""
EFFECTIVE_UNLOCK=""
EFFECTIVE_SOURCE=""

# -----------------------------
# 공용 함수
# -----------------------------
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

# key=value 형태(인라인 주석 제거 포함) 값 추출: 마지막 유효 라인 기준
extract_conf_kv_last() {
  local file="$1"
  local key="$2"
  # 1) 주석 라인 제외 2) 인라인 주석 제거 3) key = value 형태에서 value 추출 4) 마지막 값
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -E "^[[:space:]]*${key}[[:space:]]*=" \
    | tail -n 1 \
    | cut -d'=' -f2- \
    | trim
}

# PAM 라인에서 pam_faillock/pam_tally(2) 존재 여부 및 deny/unlock_time 추출(마지막 값)
extract_pam_param_last() {
  local file="$1"
  local param="$2"
  # 주석 제외 + 인라인 주석 제거 + 모듈 포함 라인에서 param=값 추출, 마지막 값
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -E 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so' \
    | grep -E "${param}=" \
    | sed -nE "s/.*${param}=([0-9]+).*/\1/p" \
    | tail -n 1 \
    | trim
}

pam_has_lock_module() {
  local file="$1"
  grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
    | sed 's/#.*$//' \
    | grep -Eq 'pam_faillock\.so|pam_tally2\.so|pam_tally\.so'
}

# -----------------------------
# 1) authselect with-faillock 확인(있으면)
# -----------------------------
if command -v authselect >/dev/null 2>&1; then
  # "Enabled features:" 아래에 with-faillock 있는지 확인(환경에 따라 출력이 다를 수 있어 유연하게)
  if authselect current 2>/dev/null | grep -Eq 'with-faillock'; then
    AUTHSELECT_WITH_FAILLOCK="enabled"
  else
    AUTHSELECT_WITH_FAILLOCK="disabled_or_unknown"
  fi
else
  AUTHSELECT_WITH_FAILLOCK="not_installed"
fi

# -----------------------------
# 2) faillock.conf에서 deny/unlock_time 확인
# -----------------------------
if [ -f "$TARGET_FILE" ]; then
  DENY_FROM_FAILLOCK_CONF="$(extract_conf_kv_last "$TARGET_FILE" "deny")"
  UNLOCK_FROM_FAILLOCK_CONF="$(extract_conf_kv_last "$TARGET_FILE" "unlock_time")"
else
  DENY_FROM_FAILLOCK_CONF="file_not_found"
  UNLOCK_FROM_FAILLOCK_CONF="file_not_found"
fi

# -----------------------------
# 3) PAM에서 모듈 적용 여부 및 deny/unlock_time 확인
# -----------------------------
PAM_APPLIED="no"
PAM_FILES_EXIST="yes"

if [ ! -f "$PAM_SYSTEM_AUTH" ] && [ ! -f "$PAM_PASSWORD_AUTH" ]; then
  PAM_FILES_EXIST="no"
else
  # 둘 중 하나라도 모듈이 있으면 적용된 것으로 간주(현장 구성 다양성 고려)
  if [ -f "$PAM_SYSTEM_AUTH" ] && pam_has_lock_module "$PAM_SYSTEM_AUTH"; then
    PAM_APPLIED="yes"
  fi
  if [ -f "$PAM_PASSWORD_AUTH" ] && pam_has_lock_module "$PAM_PASSWORD_AUTH"; then
    PAM_APPLIED="yes"
  fi
fi

# PAM 파라미터는 두 파일 중 "마지막으로 발견되는 값"을 우선(현실적으로 더 강하게 적용되는 쪽은 구성에 따라 다름)
# - system-auth 먼저, password-auth 다음 순으로 검색해 마지막 값을 "effective 후보"로 사용
if [ -f "$PAM_SYSTEM_AUTH" ]; then
  d1="$(extract_pam_param_last "$PAM_SYSTEM_AUTH" "deny")"
  u1="$(extract_pam_param_last "$PAM_SYSTEM_AUTH" "unlock_time")"
fi
if [ -f "$PAM_PASSWORD_AUTH" ]; then
  d2="$(extract_pam_param_last "$PAM_PASSWORD_AUTH" "deny")"
  u2="$(extract_pam_param_last "$PAM_PASSWORD_AUTH" "unlock_time")"
fi

# deny 후보 병합: password-auth 값이 있으면 그걸, 없으면 system-auth
if [ -n "${d2:-}" ]; then
  DENY_FROM_PAM="$d2"
elif [ -n "${d1:-}" ]; then
  DENY_FROM_PAM="$d1"
else
  DENY_FROM_PAM="not_set"
fi

# unlock_time 후보 병합
if [ -n "${u2:-}" ]; then
  UNLOCK_FROM_PAM="$u2"
elif [ -n "${u1:-}" ]; then
  UNLOCK_FROM_PAM="$u1"
else
  UNLOCK_FROM_PAM="not_set"
fi

# 모듈 적용 상태 기록
if [ "$PAM_FILES_EXIST" = "no" ]; then
  PAM_MODULE_STATUS="pam_files_not_found"
elif [ "$PAM_APPLIED" = "yes" ]; then
  PAM_MODULE_STATUS="applied"
else
  PAM_MODULE_STATUS="not_applied"
fi

# -----------------------------
# 4) 최종(effective) deny/unlock_time 결정 로직
# -----------------------------
# 일반적으로 pam_faillock.so 인자(deny/unlock_time)가 있으면 그 값이 우선.
# 없으면 /etc/security/faillock.conf 값을 사용.
# (구성 환경에 따라 다를 수 있으나, 가이드에서 두 케이스를 모두 제시하므로 실효값 판단을 이렇게 둠)

# effective deny
if is_int "$DENY_FROM_PAM"; then
  EFFECTIVE_DENY="$DENY_FROM_PAM"
  EFFECTIVE_SOURCE="pam"
elif is_int "$DENY_FROM_FAILLOCK_CONF"; then
  EFFECTIVE_DENY="$DENY_FROM_FAILLOCK_CONF"
  EFFECTIVE_SOURCE="faillock.conf"
else
  EFFECTIVE_DENY="not_set"
  EFFECTIVE_SOURCE="none"
fi

# effective unlock_time (존재 여부 중심 점검)
if is_int "$UNLOCK_FROM_PAM"; then
  EFFECTIVE_UNLOCK="$UNLOCK_FROM_PAM"
elif is_int "$UNLOCK_FROM_FAILLOCK_CONF"; then
  EFFECTIVE_UNLOCK="$UNLOCK_FROM_FAILLOCK_CONF"
else
  EFFECTIVE_UNLOCK="not_set"
fi

# -----------------------------
# 5) PASS/FAIL 판정
# -----------------------------
# 조건:
# - PAM에 잠금 모듈이 적용(applied)되어 있어야 함
# - deny가 정수이며 1~10
# - unlock_time은 "권고 구성"으로 존재 여부를 추가 점검(없으면 FAIL 처리할지에 대해 해석 여지 있으나,
#   사용자 제공 가이드에서 unlock_time 지정이 같이 제시되므로 여기서는 미설정 시 취약으로 판단)

DENY_OK="no"
UNLOCK_OK="no"
PAM_OK="no"

if [ "$PAM_MODULE_STATUS" = "applied" ]; then
  PAM_OK="yes"
fi

if is_int "$EFFECTIVE_DENY" && [ "$EFFECTIVE_DENY" -ge 1 ] && [ "$EFFECTIVE_DENY" -le 10 ]; then
  DENY_OK="yes"
fi

if is_int "$EFFECTIVE_UNLOCK" && [ "$EFFECTIVE_UNLOCK" -ge 1 ]; then
  UNLOCK_OK="yes"
fi

if [ "$PAM_OK" = "yes" ] && [ "$DENY_OK" = "yes" ] && [ "$UNLOCK_OK" = "yes" ]; then
  STATUS="PASS"
  REASON_LINE="PAM 잠금 모듈이 적용되어 있고, 계정 잠금 임계값(deny)이 ${EFFECTIVE_DENY} (1~10)으로 설정되어 있으며 unlock_time=${EFFECTIVE_UNLOCK} 로 구성되어 있어 무차별 대입 공격을 제한할 수 있으므로 양호합니다."
else
  STATUS="FAIL"

  # 실패 사유를 조합
  FAIL_REASONS=()

  if [ "$PAM_OK" != "yes" ]; then
    FAIL_REASONS+=("PAM에 pam_faillock/pam_tally(2) 모듈이 적용되어 있지 않음")
  fi

  if [ "$DENY_OK" != "yes" ]; then
    FAIL_REASONS+=("deny 설정이 없거나 비정상/권고범위(1~10) 초과 (effective_deny=${EFFECTIVE_DENY})")
  fi

  if [ "$UNLOCK_OK" != "yes" ]; then
    FAIL_REASONS+=("unlock_time 설정이 없거나 비정상 (effective_unlock_time=${EFFECTIVE_UNLOCK})")
  fi

  # 배열 -> 문장
  REASON_LINE="계정 잠금 정책 점검 결과 취약합니다: $(IFS='; '; echo "${FAIL_REASONS[*]}"). deny는 10 이하(1~10)로 설정하고 unlock_time을 지정하며, PAM 모듈(pam_faillock 또는 pam_tally2)이 실제로 적용되도록 구성해야 합니다."
fi

# -----------------------------
# 6) DETAIL(현 설정) 구성
# -----------------------------
DETAIL_CONTENT=$(cat <<EOF
authselect_with_faillock=$AUTHSELECT_WITH_FAILLOCK
pam_module_status=$PAM_MODULE_STATUS
faillock_conf_deny=${DENY_FROM_FAILLOCK_CONF}
faillock_conf_unlock_time=${UNLOCK_FROM_FAILLOCK_CONF}
pam_deny=${DENY_FROM_PAM}
pam_unlock_time=${UNLOCK_FROM_PAM}
effective_source=${EFFECTIVE_SOURCE}
effective_deny=${EFFECTIVE_DENY}
effective_unlock_time=${EFFECTIVE_UNLOCK}
EOF
)

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE, $PAM_SYSTEM_AUTH, $PAM_PASSWORD_AUTH"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
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