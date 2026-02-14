#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.4.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 전체 허용(any/*/0.0.0.0/0) 설정을 none으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -u

ID="U-51"
CATEGORY="서비스 관리"
TITLE="DNS 서비스의 취약한 동적 업데이트 설정 금지"
IMPORTANCE="중"
TARGET_FILE="N/A"

# 실행 모드:
# - no(기본): allow-update 설정을 allow-update { none; }; 로 제한 적용합니다.
# - yes: 자동 조치를 수행하지 않고 수동 조치 안내만 출력합니다.
USE_DNS_DYNAMIC_UPDATE="${USE_DNS_DYNAMIC_UPDATE:-no}"

STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."
GUIDE="allow-update 제한 설정을 적용하고 named 서비스를 재시작했습니다."
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
    if [ ! -f "${f}.bak_kisa_u51" ]; then
        cp -a "$f" "${f}.bak_kisa_u51" 2>/dev/null || true
        append_log "$f 백업 파일(${f}.bak_kisa_u51)을 생성했습니다."
    fi
}

rewrite_allow_update_to_none() {
    # allow-update 블록(단일/멀티라인)을 allow-update { none; }; 으로 치환한다.
    # 파일의 최상위에 새로 추가하지는 않는다(구문 오류 방지).
    local file="$1"
    local tmp
    tmp="$(mktemp)"

    awk '
      BEGIN { inblk=0; saw=0; }
      {
        line=$0
        if (inblk==0) {
          if (line ~ /^[[:space:]]*allow-update[[:space:]]*\\{/) {
            inblk=1
            saw=1
            print "    allow-update { none; };"
            # allow-update { ... }; 가 한 줄에 끝나는 경우도 처리
            if (line ~ /\\};[[:space:]]*$/) {
              inblk=0
            }
            next
          }
          print line
          next
        }
        # inblk==1: 원본 allow-update 블록은 버린다. 닫힘(};)까지 스킵.
        if (line ~ /\\};[[:space:]]*$/) {
          inblk=0
        }
        next
      }
      END { if (saw==0) exit 3; }
    ' "$file" >"$tmp"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        mv "$tmp" "$file"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

mode="no"
case "$USE_DNS_DYNAMIC_UPDATE" in
    yes|YES|Yes|true|TRUE|on|ON|1) mode="yes" ;;
    no|NO|No|false|FALSE|off|OFF|0) mode="no" ;;
    *) mode="no" ;;
esac

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
        if [ "$mode" = "yes" ]; then
            STATUS="MANUAL"
            ACTION_RESULT="MANUAL_REQUIRED"
            EVIDENCE="동적 업데이트 필요 환경은 자동 조치를 수행하지 않았습니다."
            GUIDE="동적 업데이트가 필요한 경우 allow-update를 허용 IP 또는 키로 제한 지정하고 named 서비스를 재시작해야 합니다."
            ACTION_LOG="USE_DNS_DYNAMIC_UPDATE=yes로 설정되어 자동 조치를 건너뛰었습니다."
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

                changed=0
                for f in "${CONF_FILES[@]}"; do
                    [ -f "$f" ] || continue
                    if grep -qE '^[[:space:]]*allow-update[[:space:]]*\\{' "$f" 2>/dev/null; then
                        backup_once "$f"
                        if rewrite_allow_update_to_none "$f"; then
                            changed=1
                            append_log "$f의 allow-update 설정을 allow-update { none; }; 으로 제한했습니다."
                        fi
                    fi
                done

                if [ "$changed" -eq 0 ]; then
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    EVIDENCE="allow-update 설정이 없어 동적 업데이트가 차단되어 있습니다."
                    GUIDE="동적 업데이트가 필요하면 allow-update를 허용 IP 또는 키로 제한 지정해야 합니다."
                    append_log "allow-update 설정이 발견되지 않아 변경 사항이 없습니다."
                else
                    if systemctl restart named >/dev/null 2>&1; then
                        append_log "named 서비스를 재시작했습니다."
                    else
                        STATUS="MANUAL"
                        ACTION_RESULT="MANUAL_REQUIRED"
                        EVIDENCE="일부 조치를 자동 적용하지 못했습니다."
                        GUIDE="allow-update 제한 설정 적용 후 named 서비스 재시작을 수동으로 수행하고 설정 구문 오류 여부를 확인해야 합니다."
                        append_log "named 서비스 재시작에 실패했습니다."
                    fi
                fi
            fi
        fi
    fi
fi

IMPACT_LEVEL="LOW"
ACTION_IMPACT="allow-update { none; }; 조치를 적용하면 DNS 동적 업데이트가 동작하지 않습니다. 동적 업데이트가 필요한 환경에서는 허용 대상을 제한 지정한 뒤 include 참조 파일을 함께 점검하고 named 재시작 절차를 반영해야 합니다."

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
