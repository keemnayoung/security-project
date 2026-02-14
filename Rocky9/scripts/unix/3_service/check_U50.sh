#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.3.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer 설정으로 Zone Transfer 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-50"
CATEGORY="서비스 관리"
TITLE="DNS Zone Transfer 설정"
IMPORTANCE="상"
TARGET_FILE="N/A"

STATUS="PASS"
EVIDENCE=""
GUIDE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

append_evidence() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    if [ -n "$EVIDENCE" ]; then
        EVIDENCE="$EVIDENCE; $msg"
    else
        EVIDENCE="$msg"
    fi
}

set_target_file_once() {
    local f="$1"
    if [ -f "$f" ] && [ "$TARGET_FILE" = "N/A" ]; then
        TARGET_FILE="$f"
        FILE_HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    fi
}

collect_named_conf_files() {
    # 1) 주 설정 파일 후보를 큐에 넣고
    # 2) include "..." 를 재귀적으로 따라가며 파일 목록을 만든다(중복 제거).
    local -a seeds=("$@")
    local -a queue=()
    local -A seen=()
    local -a out=()
    local f inc inc_path dir

    for f in "${seeds[@]}"; do
        [ -f "$f" ] || continue
        queue+=("$f")
    done

    while [ "${#queue[@]}" -gt 0 ]; do
        f="${queue[0]}"
        queue=("${queue[@]:1}")

        [ -f "$f" ] || continue
        if [ -n "${seen[$f]:-}" ]; then
            continue
        fi
        seen["$f"]=1
        out+=("$f")

        dir="$(dirname "$f")"
        while IFS= read -r inc; do
            [ -z "$inc" ] && continue
            if [[ "$inc" = /* ]]; then
                inc_path="$inc"
            else
                inc_path="${dir}/${inc}"
            fi
            [ -f "$inc_path" ] && queue+=("$inc_path")
        done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
    done

    printf '%s\n' "${out[@]}"
}

is_named_running() {
    systemctl list-units --type=service 2>/dev/null | grep -qE '\bnamed(\.service)?\b' && return 0
    pgrep -x named >/dev/null 2>&1 && return 0
    return 1
}

is_allow_transfer_wide_open() {
    # any, *, 0.0.0.0/0 류 포함 시 wide open으로 판단
    echo "$1" | grep -qE '(\bany\b|\*|0\.0\.0\.0(/0)?)'
}

json_escape() {
    echo "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")

if ! is_named_running; then
    STATUS="PASS"
    EVIDENCE="DNS(named) 서비스가 비활성화되어 점검 대상이 없습니다."
    GUIDE="DNS 미사용 환경은 named 서비스 비활성 상태를 유지해야 합니다."
else
    mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")
    if [ "${#CONF_FILES[@]}" -eq 0 ]; then
        STATUS="FAIL"
        VULNERABLE=1
        EVIDENCE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못했습니다."
        GUIDE="named 설정 파일 위치를 확인한 뒤 allow-transfer 제한 설정을 적용해야 합니다."
    else
        allow_found=0
        bad_count=0
        good_count=0

        for f in "${CONF_FILES[@]}"; do
            set_target_file_once "$f"
            # 주석 제외 + allow-transfer 라인(첫 1개)만 요약
            line="$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'allow-transfer[[:space:]]*\{' | head -n1)"
            if [ -z "$line" ]; then
                continue
            fi
            allow_found=1
            if is_allow_transfer_wide_open "$line"; then
                VULNERABLE=1
                bad_count=$((bad_count + 1))
                append_evidence "$f에서 allow-transfer 전체 허용 설정이 발견되었습니다($line)."
            else
                good_count=$((good_count + 1))
            fi
        done

        if [ "$allow_found" -eq 0 ]; then
            VULNERABLE=1
            append_evidence "allow-transfer 제한 설정이 발견되지 않았습니다."
        fi

        if [ "$VULNERABLE" -eq 1 ]; then
            STATUS="FAIL"
            if [ "$bad_count" -gt 0 ]; then
                EVIDENCE="DNS Zone Transfer 제한이 미흡합니다. $EVIDENCE"
            else
                EVIDENCE="DNS Zone Transfer 제한 설정이 없어 비인가 전송이 허용될 수 있습니다. $EVIDENCE"
            fi
            GUIDE="named.conf(options 또는 zone)에 allow-transfer { none; }; 또는 Secondary DNS만 허용하도록 설정하고 named 서비스를 재시작해야 합니다. include 참조 파일도 함께 점검해야 합니다."
        else
            STATUS="PASS"
            EVIDENCE="DNS Zone Transfer가 허용 대상으로 제한되어 있습니다."
            GUIDE="현재 제한 설정을 유지하고 include 참조 파일 변경 시 동일 정책을 적용해야 합니다."
        fi
    fi
fi

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="허용 대상 설정 오류 시 정상 Zone Transfer가 실패할 수 있으므로 Secondary DNS 목록을 확인한 뒤 적용해야 합니다."

EVIDENCE="$(json_escape "$EVIDENCE")"
GUIDE="$(json_escape "$GUIDE")"

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "$GUIDE",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
