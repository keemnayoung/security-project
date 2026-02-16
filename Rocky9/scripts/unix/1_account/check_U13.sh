#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 저장 시 SHA-512와 같은 안전한 암호화 알고리즘 사용 여부 점검
# @Criteria_Good : 암호화 알고리즘이 SHA-512로 설정되어 있고 기존 계정들도 적용된 경우
# @Criteria_Bad : 암호화 알고리즘이 MD5 등 취약한 알고리즘이거나 설정이 미비한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-13"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

DEFS_FILE="/etc/login.defs"
SHADOW_FILE="/etc/shadow"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$DEFS_FILE $SHADOW_FILE $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"

CHECK_COMMAND='
[ -f /etc/login.defs ] && grep -Ei "^[[:space:]]*ENCRYPT_METHOD[[:space:]]+" /etc/login.defs | tail -n 1 || echo "login.defs_not_found";
[ -f /etc/shadow ] && awk -F: '\''$2 ~ /^\$/ {print $1 ":" $2}'\'' /etc/shadow | head -n 5 || echo "shadow_not_found";
[ -f /etc/pam.d/system-auth ] && grep -E "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/system-auth || echo "system-auth_not_found_or_no_pam_unix";
[ -f /etc/pam.d/password-auth ] && grep -E "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/password-auth || echo "password-auth_not_found_or_no_pam_unix"
' | tr '\n' '; ' | sed 's/[[:space:]]\+/ /g'

REASON_LINE=""
DETAIL_CONTENT=""

ENCRYPT_METHOD=""
INVALID_ALGO_ACCOUNTS=""
PAM_WEAK_FILES=""
PAM_DETAIL=""

# ---- 함수: PAM에서 안전 알고리즘 옵션 존재 여부 점검 ----
# 안전 옵션: sha512 / sha256 / yescrypt
check_pam_file() {
    local file="$1"
    local result="OK"
    local lines=""

    if [ ! -f "$file" ]; then
        echo "NOT_FOUND"
        return
    fi

    # password 라인 중 pam_unix.so 포함 라인 추출
    lines=$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null)

    if [ -z "$lines" ]; then
        echo "NO_PAM_UNIX"
        return
    fi

    # 해당 라인들 중 안전 옵션 포함 여부(하나라도 있으면 OK)
    if echo "$lines" | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; then
        echo "OK"
    else
        echo "WEAK"
    fi
}

# ---- 파일 존재 여부에 따른 분기 ----
MISSING_FILES=""
[ -f "$DEFS_FILE" ] || MISSING_FILES="${MISSING_FILES}login.defs_not_found"$'\n'
[ -f "$SHADOW_FILE" ] || MISSING_FILES="${MISSING_FILES}shadow_not_found"$'\n'
[ -f "$PAM_SYSTEM_AUTH" ] || MISSING_FILES="${MISSING_FILES}system-auth_not_found"$'\n'
# password-auth는 환경에 따라 없을 수 있어 "있으면 점검"으로만 취급(필수 X)

if [ -n "$MISSING_FILES" ]; then
    STATUS="FAIL"
    REASON_LINE="암호화 정책 점검에 필요한 필수 파일(/etc/login.defs, /etc/shadow, /etc/pam.d/system-auth) 중 일부가 없어 안전한 암호화 알고리즘 적용 여부를 확인할 수 없으므로 취약합니다."
    DETAIL_CONTENT="$(printf "%s" "$MISSING_FILES" | sed '/^$/d')"
else
    # 1) /etc/login.defs ENCRYPT_METHOD 확인
    ENCRYPT_METHOD=$(grep -Ei '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | awk '{print $2}' | tail -n 1)

    # 안전 ENCRYPT_METHOD: SHA256 / SHA512 / YESCRYPT (대소문자 무시)
    DEFS_OK="N"
    if [ -n "$ENCRYPT_METHOD" ] && echo "$ENCRYPT_METHOD" | grep -Eqi '^(SHA256|SHA512|YESCRYPT)$'; then
        DEFS_OK="Y"
    fi

    # 2) /etc/shadow 해시 접두어 점검
    # 양호: $5$ (SHA-256), $6$ (SHA-512), $y$ (yescrypt)
    INVALID_ALGO_ACCOUNTS=$(awk -F: '
        $2 ~ /^\$/ && $2 !~ /^\$5\$/ && $2 !~ /^\$6\$/ && $2 !~ /^\$y\$/ {print $1}
    ' "$SHADOW_FILE" 2>/dev/null)

    # 3) PAM 설정 점검 (system-auth 필수, password-auth는 있으면 점검)
    SYS_PAM_RES=$(check_pam_file "$PAM_SYSTEM_AUTH")
    PASS_PAM_RES=$(check_pam_file "$PAM_PASSWORD_AUTH")

    PAM_OK="Y"
    PAM_WEAK_FILES=""

    if [ "$SYS_PAM_RES" != "OK" ]; then
        PAM_OK="N"
        PAM_WEAK_FILES="${PAM_WEAK_FILES}system-auth:$SYS_PAM_RES"$'\n'
    fi

    # password-auth는 존재하고 WEAK/NO_PAM_UNIX면 취약으로 반영(존재할 때만 의미 있음)
    if [ -f "$PAM_PASSWORD_AUTH" ] && [ "$PASS_PAM_RES" != "OK" ]; then
        PAM_OK="N"
        PAM_WEAK_FILES="${PAM_WEAK_FILES}password-auth:$PASS_PAM_RES"$'\n'
    fi

    # DETAIL 구성
    DETAIL_CONTENT="ENCRYPT_METHOD=${ENCRYPT_METHOD:-not_set}"$'\n'
    if [ -z "$INVALID_ALGO_ACCOUNTS" ]; then
        DETAIL_CONTENT="${DETAIL_CONTENT}shadow_hash_prefix=only_$5$_$6$_$y$ (SHA-256/SHA-512/yescrypt)"$'\n'
    else
        DETAIL_CONTENT="${DETAIL_CONTENT}shadow_weak_accounts:"$'\n'"$(printf "%s\n" "$INVALID_ALGO_ACCOUNTS" | sed 's/[[:space:]]*$//')"$'\n'
    fi

    DETAIL_CONTENT="${DETAIL_CONTENT}pam_system-auth=$SYS_PAM_RES"$'\n'
    if [ -f "$PAM_PASSWORD_AUTH" ]; then
        DETAIL_CONTENT="${DETAIL_CONTENT}pam_password-auth=$PASS_PAM_RES"$'\n'
    else
        DETAIL_CONTENT="${DETAIL_CONTENT}pam_password-auth=not_found(skip)"$'\n'
    fi

    # 최종 판정
    if [ "$DEFS_OK" = "Y" ] && [ "$PAM_OK" = "Y" ] && [ -z "$INVALID_ALGO_ACCOUNTS" ]; then
        STATUS="PASS"
        REASON_LINE="/etc/login.defs의 ENCRYPT_METHOD가 SHA-2 이상(SHA256/SHA512) 또는 yescrypt로 설정되어 있고, PAM(system-auth${PAM_PASSWORD_AUTH:+/password-auth})에서도 안전한 알고리즘 옵션이 적용되며, /etc/shadow의 해시도 안전 형식($5$/$6$/$y$)만 사용되어 양호합니다."
    else
        STATUS="FAIL"
        REASON_LINE="비밀번호 암호화 정책에서 SHA-2 이상(또는 yescrypt) 알고리즘 적용이 일부 보장되지 않아 취약합니다. ENCRYPT_METHOD, PAM 설정, /etc/shadow 해시 형식을 안전 기준으로 맞추고(필요 시 비밀번호 재설정으로 재생성) 점검해야 합니다."
        if [ "$DEFS_OK" != "Y" ]; then
            DETAIL_CONTENT="${DETAIL_CONTENT}defs_check=FAIL(need SHA256/SHA512/YESCRYPT)"$'\n'
        fi
        if [ "$PAM_OK" != "Y" ]; then
            DETAIL_CONTENT="${DETAIL_CONTENT}pam_check=FAIL"$'\n'"$(printf "%s" "$PAM_WEAK_FILES" | sed '/^$/d')"$'\n'
        fi
    fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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