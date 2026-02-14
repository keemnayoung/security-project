#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 설정이 전체 허용(any/*/0.0.0.0/0)인지 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-51"
CATEGORY="서비스 관리"
TITLE="DNS 서비스의 취약한 동적 업데이트 설정 금지"
IMPORTANCE="중"
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

is_allow_update_wide_open() {
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
        GUIDE="named 설정 파일 위치를 확인한 뒤 allow-update 설정을 점검해야 합니다."
    else
        found_any_allow_update=0
        wide_open_count=0
        restricted_count=0

        for f in "${CONF_FILES[@]}"; do
            set_target_file_once "$f"
            # allow-update는 여러 개가 있을 수 있으므로 전부 확인한다(주석 제외).
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                found_any_allow_update=1
                if is_allow_update_wide_open "$line"; then
                    VULNERABLE=1
                    wide_open_count=$((wide_open_count + 1))
                    append_evidence "$f에서 allow-update 전체 허용 설정이 발견되었습니다."
                else
                    restricted_count=$((restricted_count + 1))
                fi
            done < <(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'allow-update[[:space:]]*\{' || true)
        done

        if [ "$VULNERABLE" -eq 1 ]; then
            STATUS="FAIL"
            EVIDENCE="DNS 동적 업데이트 제한이 미흡합니다. $EVIDENCE"
            GUIDE="동적 업데이트가 불필요하면 allow-update { none; }; 로 설정하고, 필요한 경우 허용 IP 또는 키만 지정해야 합니다. include 참조 파일도 함께 점검해야 합니다."
        else
            STATUS="PASS"
            if [ "$found_any_allow_update" -eq 1 ]; then
                EVIDENCE="DNS 동적 업데이트가 제한되어 있습니다."
                GUIDE="동적 업데이트 필요 여부에 맞춰 allow-update를 none 또는 허용 IP/키로 제한 지정해야 합니다."
            else
                EVIDENCE="allow-update 설정이 없어 DNS 동적 업데이트가 차단되어 있습니다."
                GUIDE="동적 업데이트가 필요하면 allow-update를 허용 IP/키로 제한 지정해야 합니다."
            fi
        fi
    fi
fi

IMPACT_LEVEL="LOW"
ACTION_IMPACT="allow-update { none; }; 조치를 적용하면 DNS 동적 업데이트가 동작하지 않습니다. 동적 업데이트가 필요한 환경에서는 허용 대상을 제한 지정한 뒤 include 참조 파일을 함께 점검하고 named 재시작 절차를 반영해야 합니다."

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
