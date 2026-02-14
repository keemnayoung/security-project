#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.3.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer를 허용 대상으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -u

ID="U-50"
CATEGORY="서비스 관리"
TITLE="DNS Zone Transfer 설정"
IMPORTANCE="상"
TARGET_FILE="N/A"

# allow-transfer { <ACL>; };
# 기본값은 "none"으로 Zone Transfer를 차단합니다.
# 예) ALLOW_TRANSFER_ACL="10.0.0.2; 10.0.0.3"
ALLOW_TRANSFER_ACL="${ALLOW_TRANSFER_ACL:-none}"

STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."
GUIDE="named.conf(options 또는 zone)에 allow-transfer 제한 설정을 적용하고 named 서비스를 재시작했습니다."
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

append_log() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    if [ -n "$ACTION_LOG" ]; then
        ACTION_LOG="$ACTION_LOG; $msg"
    else
        ACTION_LOG="$msg"
    fi
}

json_escape() {
    echo "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

is_named_running() {
    systemctl list-units --type=service 2>/dev/null | grep -qE '\bnamed(\.service)?\b' && return 0
    pgrep -x named >/dev/null 2>&1 && return 0
    return 1
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

backup_once() {
    local f="$1"
    [ -f "$f" ] || return 0
    if [ ! -f "${f}.bak_kisa_u50" ]; then
        cp -a "$f" "${f}.bak_kisa_u50" 2>/dev/null || true
        append_log "$f 백업 파일(${f}.bak_kisa_u50)을 생성했습니다."
    fi
}

normalize_acl_inside() {
    local acl="$1"
    acl="$(echo "$acl" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    if [[ "$acl" != *";" ]]; then
        acl="${acl};"
    fi
    echo "$acl"
}

apply_allow_transfer_in_options() {
    local file="$1"
    local inside="$2"
    local stmt="    allow-transfer { ${inside} };"
    local tmp
    tmp="$(mktemp)"

    awk -v STMT="$stmt" '
      function count(s, ch,    t) { t=s; return gsub(ch,"",t); }
      BEGIN { in_opt=0; depth=0; inserted=0; }
      {
        line=$0
        if (in_opt==0 && line ~ /^[[:space:]]*options[[:space:]]*\\{/) {
          in_opt=1
          depth = count(line, "{") - count(line, "}")
          print line
          next
        }
        if (in_opt==1) {
          if (line ~ /^[[:space:]]*allow-transfer[[:space:]]*\\{/) {
            print STMT
            inserted=1
            depth += count(line, "{") - count(line, "}")
            next
          }
          # options 블록이 끝나기 직전에(닫는 }; 라인) allow-transfer가 없으면 삽입
          next_depth = depth + count(line, "{") - count(line, "}")
          # "};" 뒤에 주석이 붙는 케이스(예: "}; // end options")도 허용
          if (next_depth==0 && inserted==0 && line ~ /^[[:space:]]*\\};[[:space:]]*(#.*|\\/\\/.*)?$/) {
            print STMT
            inserted=1
            print line
            in_opt=0
            depth=0
            next
          }
          print line
          depth = next_depth
          if (depth<=0) { in_opt=0; depth=0; }
          next
        }
        print line
      }
      END { if (inserted==0) exit 3; }
    ' "$file" >"$tmp"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        mv "$tmp" "$file"
        append_log "$file의 options 블록에 allow-transfer 제한 설정을 적용했습니다."
        return 0
    fi
    rm -f "$tmp"
    return 1
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    EVIDENCE="root 권한으로 실행해야 조치가 가능합니다."
    ACTION_LOG="권한 부족으로 조치를 수행하지 못했습니다."
else
    if ! is_named_running; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="DNS(named) 서비스가 비활성화되어 조치 대상이 없습니다."
        ACTION_LOG="DNS(named) 서비스가 비활성화되어 조치 대상이 없습니다."
        GUIDE="DNS 미사용 환경은 named 서비스 비활성 상태를 유지해야 합니다."
    else
        CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
        mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

        if [ "${#CONF_FILES[@]}" -eq 0 ]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            EVIDENCE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못했습니다."
            ACTION_LOG="자동 조치 가능한 DNS 설정 파일이 없습니다."
        else
            main_conf=""
            for f in "${CONF_SEEDS[@]}"; do
                [ -f "$f" ] && main_conf="$f" && break
            done
            [ -z "$main_conf" ] && main_conf="${CONF_FILES[0]}"
            TARGET_FILE="$main_conf"

            inside="$(normalize_acl_inside "$ALLOW_TRANSFER_ACL")"
            backup_once "$main_conf"

            # 1) 주 설정 파일 options 블록에 allow-transfer를 반드시 반영
            if grep -qE '^[[:space:]]*options[[:space:]]*\\{' "$main_conf" 2>/dev/null; then
                if ! apply_allow_transfer_in_options "$main_conf" "$inside"; then
                    STATUS="MANUAL"
                    ACTION_RESULT="MANUAL_REQUIRED"
                    EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
                    append_log "options 블록에 allow-transfer를 자동 적용하지 못했습니다."
                    GUIDE="named.conf의 options 블록에 allow-transfer { none; }; 또는 Secondary DNS만 허용하도록 수동 설정한 뒤 named 서비스를 재시작해야 합니다."
                fi
            else
                STATUS="MANUAL"
                ACTION_RESULT="MANUAL_REQUIRED"
                EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
                append_log "$main_conf에서 options 블록을 찾지 못했습니다."
                GUIDE="named.conf에 options 블록을 확인한 뒤 allow-transfer 제한 설정을 수동 적용해야 합니다."
            fi

            # 2) include 파일에 wide-open allow-transfer가 이미 존재하는 경우만 안전하게 치환(추가 삽입은 하지 않음)
            if [ "$ACTION_RESULT" = "SUCCESS" ]; then
                for f in "${CONF_FILES[@]}"; do
                    [ -f "$f" ] || continue
                    if grep -qE '^[[:space:]]*allow-transfer[[:space:]]*\\{[[:space:]]*(any|\\*|0\\.0\\.0\\.0(/0)?)' "$f" 2>/dev/null; then
                        backup_once "$f"
                        sed -i -E "s|^[[:space:]]*allow-transfer[[:space:]]*\\{[^}]*\\};|    allow-transfer { ${inside} };|g" "$f" 2>/dev/null || true
                        append_log "$f의 allow-transfer 전체 허용 설정을 제한 설정으로 변경했습니다."
                    fi
                done
            fi

            # 3) named 재시작
            if [ "$ACTION_RESULT" = "SUCCESS" ]; then
                if systemctl restart named >/dev/null 2>&1; then
                    append_log "named 서비스를 재시작했습니다."
                else
                    STATUS="MANUAL"
                    ACTION_RESULT="MANUAL_REQUIRED"
                    EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
                    append_log "named 서비스 재시작에 실패했습니다."
                    GUIDE="allow-transfer 설정 적용 후 named 서비스를 수동으로 재시작하고, 설정 구문 오류 여부를 확인해야 합니다."
                fi
            fi
        fi
    fi
fi

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="Zone Transfer를 차단하거나 허용 대상을 제한하면 Secondary DNS 구성에 따라 서비스 영향이 발생할 수 있으므로 사전에 허용 대상을 확인해야 합니다."

EVIDENCE="$(json_escape "$EVIDENCE")"
GUIDE="$(json_escape "$GUIDE")"
ACTION_LOG="$(json_escape "$ACTION_LOG")"

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
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
