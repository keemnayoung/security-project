#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 패스워드 복잡성 설정
# @Description : 패스워드 복잡성 및 유효기간 설정 여부 점검
# @Criteria_Good : 패스워드 최소 길이, 복잡성, 유효기간 정책이 기준에 적합한 경우
# @Criteria_Bad : 패스워드 정책이 설정되어 있지 않거나 기준 미달인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-02"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PW_CONF="/etc/security/pwquality.conf"
PWH_CONF="/etc/security/pwhistory.conf"
LOGIN_DEFS="/etc/login.defs"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$PW_CONF $PWH_CONF $LOGIN_DEFS $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"

CHECK_COMMAND='
# pwquality.conf
grep -iv "^[[:space:]]*#" /etc/security/pwquality.conf 2>/dev/null | egrep -i "^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)[[:space:]]*="; \
grep -n "^[[:space:]]*enforce_for_root[[:space:]]*$" /etc/security/pwquality.conf 2>/dev/null; \
# pwhistory.conf
grep -iv "^[[:space:]]*#" /etc/security/pwhistory.conf 2>/dev/null | egrep -i "^(remember|file)[[:space:]]*="; \
grep -n "^[[:space:]]*enforce_for_root[[:space:]]*$" /etc/security/pwhistory.conf 2>/dev/null; \
# login.defs
grep -E "^[[:space:]]*PASS_(MAX|MIN)_DAYS[[:space:]]+" /etc/login.defs 2>/dev/null; \
# PAM
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_(pwquality|pwhistory|unix)\.so" /etc/pam.d/system-auth 2>/dev/null; \
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_(pwquality|pwhistory|unix)\.so" /etc/pam.d/password-auth 2>/dev/null; \
# 대상 계정(예외 처리)
awk -F: '\''{print $1":"$3":"$7}'\'' /etc/passwd 2>/dev/null | egrep "^(root:|[^:]+:[0-9]+:)" | head -n 50; \
awk -F: '\''{print $1":"$2}'\'' /etc/shadow 2>/dev/null | head -n 50
'

REASON_LINE=""
DETAIL_CONTENT=""
STATUS_FAIL="N"
DETAIL_LINES=""

# ---------------------------
# 공통 유틸
# ---------------------------
trim() { echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

get_kv_val_last() {
    # KEY=VALUE 형태 (공백/탭 허용)에서 마지막 값 추출
    local file="$1"
    local key="$2"
    grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
      | grep -E "^[[:space:]]*${key}[[:space:]]*=" \
      | tail -n 1 \
      | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}'
}

has_standalone_token() {
    # 파일에서 주석 제외 후 "토큰"이 단독 라인으로 존재하는지(공백 허용)
    local file="$1"
    local token="$2"
    grep -iv '^[[:space:]]*#' "$file" 2>/dev/null \
      | grep -Eq "^[[:space:]]*${token}[[:space:]]*$"
}

# PAM에서 특정 모듈 라인(주석 제외) 추출: password 스택만
pam_get_line_no_first() {
    local file="$1"
    local module="$2"  # pam_pwquality.so / pam_pwhistory.so / pam_unix.so
    grep -nEv '^[[:space:]]*#' "$file" 2>/dev/null \
      | grep -nE "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)" \
      | head -n 1 \
      | awk -F: '{print $1}'
}

pam_get_line_text_first() {
    local file="$1"
    local module="$2"
    grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null \
      | grep -E "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)" \
      | head -n 1
}

pam_has_module() {
    local file="$1"
    local module="$2"
    grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null \
      | grep -Eq "^[[:space:]]*password[[:space:]]+.*${module}([[:space:]]|$)"
}

pam_order_ok() {
    # pam_pwquality.so, pam_pwhistory.so 모듈이 pam_unix.so 보다 위에 있는지 확인
    local file="$1"
    local m1="$2"
    local m2="$3"
    local uline
    local m1line
    local m2line

    uline="$(pam_get_line_no_first "$file" "pam_unix\.so")"
    m1line="$(pam_get_line_no_first "$file" "$m1")"
    m2line="$(pam_get_line_no_first "$file" "$m2")"

    # pam_unix 없으면 순서 비교 의미가 약하므로, 모듈이 있으면 PASS, 없으면 FAIL은 상위에서 처리
    if [ -z "$uline" ]; then
        echo "UNKNOWN"
        return 0
    fi

    # 각 모듈이 존재하면 pam_unix 보다 위에 있어야 함
    if [ -n "$m1line" ] && [ "$m1line" -gt "$uline" ]; then
        echo "NO"
        return 0
    fi
    if [ -n "$m2line" ] && [ "$m2line" -gt "$uline" ]; then
        echo "NO"
        return 0
    fi
    echo "YES"
}

# ---------------------------
# (추가) 대상 계정/예외 처리(요청하신 3번 항목)
# - 잠금/비밀번호 미설정 계정, nologin/false 쉘 계정은 정책 적용 대상에서 제외(표기만)
# ---------------------------
SUBJECT_USERS=""
EXCLUDED_USERS=""

if [ -r /etc/passwd ] && [ -r /etc/shadow ]; then
    while IFS=: read -r user _ uid _ _ _ shell; do
        # 대상: root 또는 일반 사용자(UID>=1000)
        if [ "$user" != "root" ] && [ "$uid" -lt 1000 ] 2>/dev/null; then
            continue
        fi

        # 쉘이 비대화형이면 제외
        case "$shell" in
            */nologin|*/false|"")
                EXCLUDED_USERS+="${user}(non_login_shell:${shell}), "
                continue
                ;;
        esac

        # shadow 상태 확인
        spw="$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null)"
        if [ -z "$spw" ]; then
            EXCLUDED_USERS+="${user}(shadow_not_found), "
            continue
        fi
        # 잠금/미사용 처리: !, !!, *, 빈값 등
        case "$spw" in
            "!"*|"!!"*|"*"|"*LK*"|"")
                EXCLUDED_USERS+="${user}(locked_or_no_password), "
                continue
                ;;
        esac

        SUBJECT_USERS+="${user}, "
    done < /etc/passwd

    SUBJECT_USERS="$(echo "$SUBJECT_USERS" | sed 's/, $//')"
    EXCLUDED_USERS="$(echo "$EXCLUDED_USERS" | sed 's/, $//')"

    DETAIL_LINES+="[대상 계정] ${SUBJECT_USERS:-none}"$'\n'
    DETAIL_LINES+="[제외 계정] ${EXCLUDED_USERS:-none}"$'\n'
else
    DETAIL_LINES+="[대상/제외 계정] passwd/shadow 접근 불가"$'\n'
fi

# ---------------------------
# 1) pwquality.conf 점검
# - 가이드 기준: minlen=8, d/u/l/o credit=-1, enforce_for_root
# ---------------------------
PWQ_OK="N"
PWQ_SRC="NONE"

MINLEN_VAL=""
MINCLASS_VAL=""
DCREDIT_VAL=""
UCREDIT_VAL=""
LCREDIT_VAL=""
OCREDIT_VAL=""
PWQ_ENFORCE="N"

if [ -f "$PW_CONF" ]; then
    MINLEN_VAL="$(get_kv_val_last "$PW_CONF" "minlen")"
    MINCLASS_VAL="$(get_kv_val_last "$PW_CONF" "minclass")"
    DCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "dcredit")"
    UCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "ucredit")"
    LCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "lcredit")"
    OCREDIT_VAL="$(get_kv_val_last "$PW_CONF" "ocredit")"
    if has_standalone_token "$PW_CONF" "enforce_for_root"; then
        PWQ_ENFORCE="Y"
    fi

    # 값 출력(근거용)
    DETAIL_LINES+="[pwquality.conf] minlen=${MINLEN_VAL:-not_set} (expected>=8)"$'\n'
    DETAIL_LINES+="[pwquality.conf] minclass=${MINCLASS_VAL:-not_set} (reference only)"$'\n'
    DETAIL_LINES+="[pwquality.conf] dcredit=${DCREDIT_VAL:-not_set} (expected=-1)"$'\n'
    DETAIL_LINES+="[pwquality.conf] ucredit=${UCREDIT_VAL:-not_set} (expected=-1)"$'\n'
    DETAIL_LINES+="[pwquality.conf] lcredit=${LCREDIT_VAL:-not_set} (expected=-1)"$'\n'
    DETAIL_LINES+="[pwquality.conf] ocredit=${OCREDIT_VAL:-not_set} (expected=-1)"$'\n'
    DETAIL_LINES+="[pwquality.conf] enforce_for_root=${PWQ_ENFORCE} (expected=Y)"$'\n'

    # 판정(가이드 레드햇 절차 중심)
    if [ -n "$MINLEN_VAL" ] && [ "$MINLEN_VAL" -ge 8 ] 2>/dev/null \
       && [ "$DCREDIT_VAL" = "-1" ] && [ "$UCREDIT_VAL" = "-1" ] && [ "$LCREDIT_VAL" = "-1" ] && [ "$OCREDIT_VAL" = "-1" ] \
       && [ "$PWQ_ENFORCE" = "Y" ]; then
        PWQ_OK="Y"
        PWQ_SRC="pwquality.conf"
    fi
else
    DETAIL_LINES+="[pwquality.conf] file_not_found"$'\n'
fi

# ---------------------------
# 2) pwhistory.conf 점검
# - 가이드 기준: remember=4, file=/etc/security/opasswd, enforce_for_root
# ---------------------------
PWH_OK="N"
PWH_SRC="NONE"

REMEMBER_VAL=""
OPASSWD_FILE_VAL=""
PWH_ENFORCE="N"

if [ -f "$PWH_CONF" ]; then
    REMEMBER_VAL="$(get_kv_val_last "$PWH_CONF" "remember")"
    OPASSWD_FILE_VAL="$(get_kv_val_last "$PWH_CONF" "file")"
    if has_standalone_token "$PWH_CONF" "enforce_for_root"; then
        PWH_ENFORCE="Y"
    fi

    DETAIL_LINES+="[pwhistory.conf] remember=${REMEMBER_VAL:-not_set} (expected>=4)"$'\n'
    DETAIL_LINES+="[pwhistory.conf] file=${OPASSWD_FILE_VAL:-not_set} (expected=/etc/security/opasswd)"$'\n'
    DETAIL_LINES+="[pwhistory.conf] enforce_for_root=${PWH_ENFORCE} (expected=Y)"$'\n'

    # remember는 최소 4 이상으로 허용(가이드 예시는 4)
    if [ -n "$REMEMBER_VAL" ] && [ "$REMEMBER_VAL" -ge 4 ] 2>/dev/null \
       && [ "$OPASSWD_FILE_VAL" = "/etc/security/opasswd" ] \
       && [ "$PWH_ENFORCE" = "Y" ]; then
        PWH_OK="Y"
        PWH_SRC="pwhistory.conf"
    fi
else
    DETAIL_LINES+="[pwhistory.conf] file_not_found"$'\n'
fi

# ---------------------------
# 3) login.defs PASS_MAX_DAYS / PASS_MIN_DAYS 점검
# - 가이드 기준: MAX<=90, MIN>=1(예시 1일)
# ---------------------------
MAX_DAYS_VAL=""
MIN_DAYS_VAL=""

if [ -f "$LOGIN_DEFS" ]; then
    MAX_DAYS_VAL="$(grep -E '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}' | tail -n 1)"
    MIN_DAYS_VAL="$(grep -E '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+' "$LOGIN_DEFS" 2>/dev/null | awk '{print $2}' | tail -n 1)"

    DETAIL_LINES+="[login.defs] PASS_MAX_DAYS=${MAX_DAYS_VAL:-not_set} (expected<=90)"$'\n'
    DETAIL_LINES+="[login.defs] PASS_MIN_DAYS=${MIN_DAYS_VAL:-not_set} (expected>=1)"$'\n'
else
    STATUS_FAIL="Y"
    DETAIL_LINES+="[login.defs] file_not_found"$'\n'
fi

# login.defs 판정(값이 없으면 FAIL)
if [ -z "$MAX_DAYS_VAL" ]; then
    STATUS_FAIL="Y"
    DETAIL_LINES+="[login.defs] FAIL: PASS_MAX_DAYS not_set"$'\n'
elif [ "$MAX_DAYS_VAL" -gt 90 ] 2>/dev/null; then
    STATUS_FAIL="Y"
    DETAIL_LINES+="[login.defs] FAIL: PASS_MAX_DAYS=$MAX_DAYS_VAL (expected<=90)"$'\n'
fi

if [ -z "$MIN_DAYS_VAL" ]; then
    STATUS_FAIL="Y"
    DETAIL_LINES+="[login.defs] FAIL: PASS_MIN_DAYS not_set"$'\n'
elif [ "$MIN_DAYS_VAL" -lt 1 ] 2>/dev/null; then
    STATUS_FAIL="Y"
    DETAIL_LINES+="[login.defs] FAIL: PASS_MIN_DAYS=$MIN_DAYS_VAL (expected>=1)"$'\n'
fi

# ---------------------------
# 4) PAM 적용 점검(system-auth, password-auth)
# - pam_pwquality.so / pam_pwhistory.so 존재 여부 및 pam_unix.so 위에 위치
# - 또한, pwquality/pwhistory가 conf에 없더라도 PAM에 설정되어 있으면 "설정됨"으로 인정
# ---------------------------
PAM_FILES=("$PAM_SYSTEM_AUTH" "$PAM_PASSWORD_AUTH")
PAM_PWQ_OK="N"
PAM_PWH_OK="N"
PAM_ORDER_OK_ALL="Y"
PAM_FOUND_ANY="N"

for pf in "${PAM_FILES[@]}"; do
    if [ -f "$pf" ]; then
        PAM_FOUND_ANY="Y"
        DETAIL_LINES+="[PAM] file=$pf"$'\n'

        # 모듈 존재
        if pam_has_module "$pf" "pam_pwquality\.so"; then
            PAM_PWQ_OK="Y"
            line="$(pam_get_line_text_first "$pf" "pam_pwquality\.so")"
            DETAIL_LINES+="[PAM] pam_pwquality.so: present | ${line}"$'\n'

            # PAM 라인에 enforce_for_root가 있으면 참고 표시(강제 판단은 conf 또는 pam 중 하나라도 있으면 OK)
            echo "$line" | grep -q 'enforce_for_root' && DETAIL_LINES+="[PAM] pam_pwquality.so enforce_for_root: present"$'\n'
        else
            DETAIL_LINES+="[PAM] pam_pwquality.so: not_found"$'\n'
        fi

        if pam_has_module "$pf" "pam_pwhistory\.so"; then
            PAM_PWH_OK="Y"
            line="$(pam_get_line_text_first "$pf" "pam_pwhistory\.so")"
            DETAIL_LINES+="[PAM] pam_pwhistory.so: present | ${line}"$'\n'
            echo "$line" | grep -q 'enforce_for_root' && DETAIL_LINES+="[PAM] pam_pwhistory.so enforce_for_root: present"$'\n'
        else
            DETAIL_LINES+="[PAM] pam_pwhistory.so: not_found"$'\n'
        fi

        # 순서 점검
        order_res="$(pam_order_ok "$pf" "pam_pwquality\.so" "pam_pwhistory\.so")"
        if [ "$order_res" = "NO" ]; then
            PAM_ORDER_OK_ALL="N"
            DETAIL_LINES+="[PAM] FAIL: pam_pwquality/pwhistory must be above pam_unix.so"$'\n'
        elif [ "$order_res" = "UNKNOWN" ]; then
            DETAIL_LINES+="[PAM] WARN: pam_unix.so not found in password stack (order check skipped)"$'\n'
        else
            DETAIL_LINES+="[PAM] order: OK"$'\n'
        fi
    else
        DETAIL_LINES+="[PAM] file=$pf not_found"$'\n'
    fi
done

# PAM 파일이 하나도 없으면(드문 케이스) FAIL 처리
if [ "$PAM_FOUND_ANY" = "N" ]; then
    STATUS_FAIL="Y"
    DETAIL_LINES+="[PAM] FAIL: no PAM policy file found (system-auth/password-auth)"$'\n'
fi

# 순서 불일치면 FAIL
if [ "$PAM_ORDER_OK_ALL" = "N" ]; then
    STATUS_FAIL="Y"
fi

# pwquality/pwhistory 정책 “존재” 판단:
# - conf 기준 충족 또는 PAM에 모듈이 존재하면(가이드 주석 취지: 어느 한쪽에라도 설정되어 있으면) 정책 존재로 인정
if [ "$PWQ_OK" = "Y" ] || [ "$PAM_PWQ_OK" = "Y" ]; then
    DETAIL_LINES+="[pwquality 정책] configured_by=${PWQ_SRC:-none}, pam_present=${PAM_PWQ_OK}"$'\n'
else
    STATUS_FAIL="Y"
    DETAIL_LINES+="[pwquality 정책] FAIL: pwquality policy not configured (no valid pwquality.conf and no PAM module)"$'\n'
fi

if [ "$PWH_OK" = "Y" ] || [ "$PAM_PWH_OK" = "Y" ]; then
    DETAIL_LINES+="[pwhistory 정책] configured_by=${PWH_SRC:-none}, pam_present=${PAM_PWH_OK}"$'\n'
else
    STATUS_FAIL="Y"
    DETAIL_LINES+="[pwhistory 정책] FAIL: pwhistory policy not configured (no valid pwhistory.conf and no PAM module)"$'\n'
fi

# ---------------------------
# 최종 판단 및 평가 이유
# ---------------------------
if [ "$STATUS_FAIL" = "Y" ]; then
    STATUS="FAIL"
    REASON_LINE="비밀번호 복잡성(pwquality) 및 재사용 제한(pwhistory) 정책 또는 PAM 적용/순서, 비밀번호 유효기간(login.defs PASS_MAX_DAYS/PASS_MIN_DAYS) 설정이 가이드 기준을 충족하지 않거나 확인되지 않아 약한 비밀번호 사용·재사용 및 장기간 미변경으로 인한 계정 탈취 위험이 증가하므로 취약합니다. (pwquality: minlen>=8, credit=-1, enforce_for_root / pwhistory: remember>=4, file=/etc/security/opasswd, enforce_for_root / PAM: pwquality·pwhistory가 pam_unix 위 / login.defs: PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1)"
else
    STATUS="PASS"
    REASON_LINE="비밀번호 복잡성(pwquality), 재사용 제한(pwhistory), PAM 적용/순서, 비밀번호 유효기간(PASS_MAX_DAYS/PASS_MIN_DAYS) 설정이 가이드 기준을 충족하여 약한 비밀번호 사용 및 장기간 미변경/재사용 위험이 낮으므로 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$(echo "$CHECK_COMMAND" | sed ':a;N;$!ba;s/\n/ /g' | sed 's/  */ /g')",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
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