#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-37 crontab 설정파일 권한 설정

# 1. 항목 정보 정의
ID="U-37"
CATEGORY="서비스 관리"
TITLE="crontab 설정파일 권한 설정 미흡"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
STATUS="PASS"
EVIDENCE="crontab 및 at 관련 파일의 권한이 적절히 설정되어 있습니다."

append_log() {
    if [ -n "$ACTION_LOG" ]; then
        ACTION_LOG="$ACTION_LOG $1"
    else
        ACTION_LOG="$1"
    fi
}

fail() {
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    if [ -n "$1" ]; then
        append_log "$1"
    fi
}

check_perm_exceeds() {
    local current="$1"
    local max="$2"
    [ -n "$current" ] || return 0
    [ "$current" -gt "$max" ] && return 0 || return 1
}

ensure_owner_root() {
    local f="$1"
    if [ -e "$f" ]; then
        chown root "$f" 2>/dev/null || fail "$f 소유자를 root로 변경하지 못했습니다."
    fi
}

ensure_mode() {
    local f="$1"
    local mode="$2"
    if [ -e "$f" ]; then
        chmod "$mode" "$f" 2>/dev/null || fail "$f 권한을 ${mode}로 변경하지 못했습니다."
    fi
}

verify_cmd() {
    local f="$1"
    if [ -f "$f" ]; then
        local owner perms
        owner="$(stat -c '%U' "$f" 2>/dev/null || true)"
        perms="$(stat -c '%a' "$f" 2>/dev/null || true)"
        if [ "$owner" != "root" ]; then
            fail "$f 소유자가 root가 아닙니다(현재: $owner)."
        fi
        if check_perm_exceeds "$perms" 750; then
            fail "$f 권한이 750을 초과합니다(현재: $perms)."
        fi
    fi
}

verify_file() {
    local f="$1"
    local max="$2"
    if [ -f "$f" ]; then
        local owner perms
        owner="$(stat -c '%U' "$f" 2>/dev/null || true)"
        perms="$(stat -c '%a' "$f" 2>/dev/null || true)"
        if [ "$owner" != "root" ]; then
            fail "$f 소유자가 root가 아닙니다(현재: $owner)."
        fi
        if check_perm_exceeds "$perms" "$max"; then
            fail "$f 권한이 ${max}을 초과합니다(현재: $perms)."
        fi
    fi
}

verify_dir() {
    local d="$1"
    local max="$2"
    if [ -d "$d" ]; then
        local owner perms
        owner="$(stat -c '%U' "$d" 2>/dev/null || true)"
        perms="$(stat -c '%a' "$d" 2>/dev/null || true)"
        if [ "$owner" != "root" ]; then
            fail "$d 소유자가 root가 아닙니다(현재: $owner)."
        fi
        if check_perm_exceeds "$perms" "$max"; then
            fail "$d 권한이 ${max}을 초과합니다(현재: $perms)."
        fi
    fi
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    EVIDENCE="root 권한으로 실행해야 조치가 가능합니다."
    ACTION_LOG="권한이 부족하여 조치를 수행할 수 없습니다. sudo로 실행해야 합니다."
    echo ""
    cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "sudo로 실행한 뒤, crontab/at 관련 파일 권한을 640 이하(디렉토리 750 이하), 소유자를 root로 설정해야 합니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    exit 1
fi

# [Step 3] crontab 명령어 소유자 root, 권한 750으로 변경
# 가이드: SUID 설정 제거 필요
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
    ensure_owner_root "$CRONTAB_CMD"
    ensure_mode "$CRONTAB_CMD" 750
    AFTER="$(stat -c '%U:%a' "$CRONTAB_CMD" 2>/dev/null || true)"
    append_log "$CRONTAB_CMD 권한을 root:750 기준으로 설정했습니다(현재: $AFTER)."
fi

# [Step 3] at 명령어 소유자 root, 권한 750으로 변경
# 가이드: SUID 설정 제거 필요
AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
    ensure_owner_root "$AT_CMD"
    ensure_mode "$AT_CMD" 750
    AFTER="$(stat -c '%U:%a' "$AT_CMD" 2>/dev/null || true)"
    append_log "$AT_CMD 권한을 root:750 기준으로 설정했습니다(현재: $AFTER)."
fi

# [Step 4] cron 작업 목록 파일 소유자 root, 권한 640으로 변경
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for dir in "${CRON_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                ensure_owner_root "$f"
                ensure_mode "$f" 640
            fi
        done
    fi
done
append_log "cron spool 파일(/var/spool/cron*)을 root:640 기준으로 설정했습니다."

# [Step 4] /etc/<cron 관련 파일> 소유자 root, 권한 640으로 변경
CRON_ETC_FILES=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for f in "${CRON_ETC_FILES[@]}"; do
    if [ -e "$f" ]; then
        ensure_owner_root "$f"
        if [ -d "$f" ]; then
            ensure_mode "$f" 750
        else
            ensure_mode "$f" 640
        fi
    fi
done
append_log "/etc/crontab 및 /etc/cron.* 을 파일 640, 디렉토리 750 기준으로 설정했습니다."

# [Step 4] at 작업 목록 파일 소유자 root, 권한 640으로 변경
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for dir in "${AT_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                ensure_owner_root "$f"
                ensure_mode "$f" 640
            fi
        done
    fi
done
append_log "at spool 파일(/var/spool/at*, /var/spool/cron/atjobs)을 root:640 기준으로 설정했습니다."

# [검증]
verify_cmd "/usr/bin/crontab"
verify_cmd "/usr/bin/at"

CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for dir in "${CRON_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            [ -f "$f" ] || continue
            verify_file "$f" 640
        done
    fi
done

CRON_ETC_FILES=("/etc/crontab")
for f in "${CRON_ETC_FILES[@]}"; do
    verify_file "$f" 640
done

CRON_ETC_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for d in "${CRON_ETC_DIRS[@]}"; do
    verify_dir "$d" 750
done

AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for dir in "${AT_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            [ -f "$f" ] || continue
            verify_file "$f" 640
        done
    fi
done

if [ "$STATUS" = "FAIL" ]; then
    EVIDENCE="조치 후에도 일부 항목이 기준을 만족하지 않습니다."
else
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="crontab 및 at 관련 파일의 권한이 적절히 설정되어 있습니다."
fi

# 출력 정리: 대시보드가 문장을 분리할 때 ';'가 노이즈로 보이므로 제거합니다.
ACTION_LOG=$(echo "$ACTION_LOG" | tr ';' ' ' | tr -s ' ' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
