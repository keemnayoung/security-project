#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-07
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 불필요한 계정 제거
# @Description : 시스템에 기본적으로 생성되어 있으나 사용하지 않는 계정(lp, uucp 등)의 존재 여부 점검
# @Criteria_Good : 불필요한 계정이 삭제되거나 잠금 설정된 경우
# @Criteria_Bad : 불필요한 계정이 활성화되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-07"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
# (기존 값 유지) 기본 계정 존재 여부 1차 체크용
CHECK_COMMAND='[ -f /etc/passwd ] && egrep "^(lp|uucp|nuucp):" /etc/passwd || echo "passwd_not_found_or_no_matches"'

REASON_LINE=""
DETAIL_CONTENT=""

DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

# ---- 추가 확장: 로그인 가능/미사용 계정 점검을 위한 변수 ----
UNUSED_DAYS=90

NONLOGIN_SHELLS=(
  "/sbin/nologin"
  "/usr/sbin/nologin"
  "/bin/false"
  "/usr/bin/false"
)

DEFAULT_LOGINABLE_ACCOUNTS=()   # "user:shell"
DEFAULT_NONLOGIN_ACCOUNTS=()    # "user:shell"
UNUSED_INTERACTIVE_ACCOUNTS=()  # "user:uid:shell:lastlog_detail"
WARNINGS=()

is_nonlogin_shell() {
  local sh="$1"
  for s in "${NONLOGIN_SHELLS[@]}"; do
    [ "$sh" = "$s" ] && return 0
  done
  return 1
}

# 파일 존재 여부에 따른 분기
if [ -f "$TARGET_FILE" ]; then
    # 1) 불필요 기본 계정 존재 여부 점검(기존 로직 유지)
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE" 2>/dev/null; then
            FOUND_ACCOUNTS+=("$acc")

            # ---- 추가: 기본 계정의 로그인 가능 여부(쉘) 점검 ----
            shell="$(awk -F: -v u="$acc" '$1==u{print $7}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            [ -z "$shell" ] && shell="unknown"

            if is_nonlogin_shell "$shell"; then
                DEFAULT_NONLOGIN_ACCOUNTS+=("${acc}:${shell}")
            else
                DEFAULT_LOGINABLE_ACCOUNTS+=("${acc}:${shell}")
            fi
        fi
    done

    # 2) 장기간 미사용 계정 점검(lastlog 우선, 없으면 last 보조)
    if command -v lastlog >/dev/null 2>&1; then
        # lastlog -b N : N일 이전 마지막 로그인 사용자(및 환경에 따라 Never logged in 포함)
        mapfile -t LL_USERS < <(lastlog -b "$UNUSED_DAYS" 2>/dev/null | awk 'NR>1 && $1!="" {print $1}' | sort -u)

        for u in "${LL_USERS[@]}"; do
            # /etc/passwd에 존재하는 사용자만
            if ! grep -q "^${u}:" "$TARGET_FILE" 2>/dev/null; then
                continue
            fi

            uid="$(awk -F: -v user="$u" '$1==user{print $3}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            shell="$(awk -F: -v user="$u" '$1==user{print $7}' "$TARGET_FILE" 2>/dev/null | head -n 1)"
            [ -z "$uid" ] && continue
            [ -z "$shell" ] && shell="unknown"

            # 일반 사용자(UID 1000 이상)만 대상으로(요청 프로젝트 기준에 맞춰 기본 적용)
            if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -ne 65534 ] 2>/dev/null; then
                # 로그인 가능한 쉘만 "미사용 계정 후보"로 분류
                if ! is_nonlogin_shell "$shell"; then
                    ll_detail="$(lastlog -u "$u" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]\+/ /g' | sed 's/^ //;s/ $//')"
                    [ -z "$ll_detail" ] && ll_detail="lastlog_detail_unavailable"
                    UNUSED_INTERACTIVE_ACCOUNTS+=("${u}:${uid}:${shell}:${ll_detail}")
                fi
            fi
        done
    else
        WARNINGS+=("lastlog_not_found")
        # last는 참고용(미사용 판정 대체는 어려움)
        if ! command -v last >/dev/null 2>&1; then
            WARNINGS+=("last_not_found")
        fi
    fi

    # 3) 결과에 따른 PASS/FAIL 결정 (확장 반영)
    #    - 기본 계정이 존재하더라도 nologin/false면 즉시 취약으로 보지 않고 참고로만 기록
    #    - 기본 계정이 "로그인 가능"이면 취약
    #    - 장기간 미사용(UNUSED_DAYS)인 "로그인 가능 일반 사용자(UID>=1000)"가 있으면 취약
    if [ ${#DEFAULT_LOGINABLE_ACCOUNTS[@]} -gt 0 ] || [ ${#UNUSED_INTERACTIVE_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        REASON_LINE="불필요 계정(기본 계정의 로그인 가능 상태 또는 장기간 미사용 대화형 계정)이 확인되어 계정 오남용 및 불필요한 접근 경로가 될 수 있으므로 취약합니다. 사용 여부를 확인한 뒤 불필요하면 삭제하거나 로그인 불가(nologin/false)로 전환해야 합니다."

        # DETAIL_CONTENT 구성(기존처럼 문자열 한 덩어리, 줄바꿈 포함)
        DETAIL_CONTENT=$(
cat <<EOF
[default_accounts_found]
$(printf "%s\n" "${FOUND_ACCOUNTS[@]}" 2>/dev/null)

[default_accounts_loginable]
$(printf "%s\n" "${DEFAULT_LOGINABLE_ACCOUNTS[@]}" 2>/dev/null)

[default_accounts_nonlogin]
$(printf "%s\n" "${DEFAULT_NONLOGIN_ACCOUNTS[@]}" 2>/dev/null)

[unused_interactive_accounts_over_${UNUSED_DAYS}d_uid>=1000]
$(printf "%s\n" "${UNUSED_INTERACTIVE_ACCOUNTS[@]}" 2>/dev/null)

[warnings]
$(printf "%s\n" "${WARNINGS[@]}" 2>/dev/null)
EOF
)
    else
        STATUS="PASS"
        REASON_LINE="불필요한 기본 계정(lp, uucp, nuucp)이 로그인 가능 상태로 존재하지 않고, 장기간 미사용(기준 ${UNUSED_DAYS}일)인 대화형 일반 사용자 계정도 확인되지 않아 양호합니다."

        DETAIL_CONTENT=$(
cat <<EOF
no_vulnerable_unused_accounts

[default_accounts_nonlogin_only]
$(printf "%s\n" "${DEFAULT_NONLOGIN_ACCOUNTS[@]}" 2>/dev/null)

[warnings]
$(printf "%s\n" "${WARNINGS[@]}" 2>/dev/null)
EOF
)
    fi
else
    STATUS="FAIL"
    REASON_LINE="사용자 정보 파일(/etc/passwd)이 존재하지 않아 불필요 계정 존재 여부를 점검할 수 없으므로 취약합니다. /etc/passwd 파일을 복구한 뒤 기본 불필요 계정 및 미사용 계정 존재 여부를 점검해야 합니다."
    DETAIL_CONTENT="passwd_not_found"
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