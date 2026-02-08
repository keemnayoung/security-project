#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : crontab 설정파일 권한 설정
# @Description : crontab/at 파일의 소유자와 권한을 적절히 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-37 crontab 설정파일 권한 설정

# 1. 항목 정보 정의
ID="U-37"
CATEGORY="서비스관리"
TITLE="crontab 설정파일 권한 설정"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [Step 3] crontab 명령어 소유자 root, 권한 750으로 변경
# 가이드: SUID 설정 제거 필요
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
    BEFORE=$(stat -c '%U:%a' "$CRONTAB_CMD" 2>/dev/null)
    BEFORE_SETTING="$BEFORE_SETTING $CRONTAB_CMD($BEFORE);"
    chown root "$CRONTAB_CMD" 2>/dev/null
    chmod 750 "$CRONTAB_CMD" 2>/dev/null
    AFTER=$(stat -c '%U:%a' "$CRONTAB_CMD" 2>/dev/null)
    ACTION_LOG="$ACTION_LOG $CRONTAB_CMD->$AFTER;"
fi

# [Step 3] at 명령어 소유자 root, 권한 750으로 변경
# 가이드: SUID 설정 제거 필요
AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
    BEFORE=$(stat -c '%U:%a' "$AT_CMD" 2>/dev/null)
    BEFORE_SETTING="$BEFORE_SETTING $AT_CMD($BEFORE);"
    chown root "$AT_CMD" 2>/dev/null
    chmod 750 "$AT_CMD" 2>/dev/null
    AFTER=$(stat -c '%U:%a' "$AT_CMD" 2>/dev/null)
    ACTION_LOG="$ACTION_LOG $AT_CMD->$AFTER;"
fi

# [Step 4] cron 작업 목록 파일 소유자 root, 권한 640으로 변경
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for dir in "${CRON_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                BEFORE=$(stat -c '%U:%a' "$f" 2>/dev/null)
                BEFORE_SETTING="$BEFORE_SETTING $f($BEFORE);"
                chown root "$f" 2>/dev/null
                chmod 640 "$f" 2>/dev/null
                AFTER=$(stat -c '%U:%a' "$f" 2>/dev/null)
                ACTION_LOG="$ACTION_LOG $f->$AFTER;"
            fi
        done
    fi
done

# [Step 4] /etc/<cron 관련 파일> 소유자 root, 권한 640으로 변경
CRON_ETC_FILES=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for f in "${CRON_ETC_FILES[@]}"; do
    if [ -e "$f" ]; then
        BEFORE=$(stat -c '%U:%a' "$f" 2>/dev/null)
        BEFORE_SETTING="$BEFORE_SETTING $f($BEFORE);"
        chown root "$f" 2>/dev/null
        if [ -d "$f" ]; then
            chmod 750 "$f" 2>/dev/null
        else
            chmod 640 "$f" 2>/dev/null
        fi
        AFTER=$(stat -c '%U:%a' "$f" 2>/dev/null)
        ACTION_LOG="$ACTION_LOG $f->$AFTER;"
    fi
done

# [Step 4] at 작업 목록 파일 소유자 root, 권한 640으로 변경
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for dir in "${AT_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                BEFORE=$(stat -c '%U:%a' "$f" 2>/dev/null)
                BEFORE_SETTING="$BEFORE_SETTING $f($BEFORE);"
                chown root "$f" 2>/dev/null
                chmod 640 "$f" 2>/dev/null
                AFTER=$(stat -c '%U:%a' "$f" 2>/dev/null)
                ACTION_LOG="$ACTION_LOG $f->$AFTER;"
            fi
        done
    fi
done

AFTER_SETTING="crontab/at 파일 권한 조정 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="이미 적절한 권한이 설정된 상태"

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
