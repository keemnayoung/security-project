#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 적절성 여부 점검
# @Criteria_Good : crontab/at 명령어 권한 750 이하, 관련 파일 권한 640 이하
# @Criteria_Bad : 권한이 과다하게 부여된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-37 crontab 설정파일 권한 설정

# 1. 항목 정보 정의
ID="U-37"
CATEGORY="서비스관리"
TITLE="crontab 설정파일 권한 설정 미흡"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# 권한 비교 함수 (8진수 비교)
check_perm_exceeds() {
    local current=$1
    local max=$2
    [ "$current" -gt "$max" ] && return 0 || return 1
}

# [Step 1] crontab 명령어 소유자 및 권한 확인
# 가이드: ls -l /usr/bin/crontab (권한 750 이하, 소유자 root)
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
    OWNER=$(stat -c '%U' "$CRONTAB_CMD" 2>/dev/null)
    PERMS=$(stat -c '%a' "$CRONTAB_CMD" 2>/dev/null)
    if [ "$OWNER" != "root" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $CRONTAB_CMD 소유자 root 아님($OWNER);"
    fi
    if check_perm_exceeds "$PERMS" 750; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $CRONTAB_CMD 권한 과다($PERMS>750);"
    fi
fi

# [Step 1] cron 작업 목록 파일 소유자 및 권한 확인
# 가이드: ls -l /var/spool/cron/<파일>, /var/spool/cron/crontabs/<파일> (권한 640 이하)
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for dir in "${CRON_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                OWNER=$(stat -c '%U' "$f" 2>/dev/null)
                PERMS=$(stat -c '%a' "$f" 2>/dev/null)
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f 소유자 root 아님($OWNER);"
                fi
                if check_perm_exceeds "$PERMS" 640; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f 권한 과다($PERMS>640);"
                fi
            fi
        done
    fi
done

# [Step 1] /etc/<cron 관련 파일> 소유자 및 권한 확인
# 가이드: ls -l /etc/<cron 관련 파일> (권한 640 이하)
CRON_ETC_FILES=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for f in "${CRON_ETC_FILES[@]}"; do
    if [ -e "$f" ]; then
        OWNER=$(stat -c '%U' "$f" 2>/dev/null)
        PERMS=$(stat -c '%a' "$f" 2>/dev/null)
        if [ "$OWNER" != "root" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $f 소유자 root 아님($OWNER);"
        fi
        if [ -d "$f" ]; then
            # 디렉토리는 750 이하
            if check_perm_exceeds "$PERMS" 750; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $f 권한 과다($PERMS>750);"
            fi
        else
            # 파일은 640 이하
            if check_perm_exceeds "$PERMS" 640; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $f 권한 과다($PERMS>640);"
            fi
        fi
    fi
done

# [Step 2] at 명령어 소유자 및 권한 확인
# 가이드: ls -l /usr/bin/at (권한 750 이하, 소유자 root)
AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
    OWNER=$(stat -c '%U' "$AT_CMD" 2>/dev/null)
    PERMS=$(stat -c '%a' "$AT_CMD" 2>/dev/null)
    if [ "$OWNER" != "root" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $AT_CMD 소유자 root 아님($OWNER);"
    fi
    if check_perm_exceeds "$PERMS" 750; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $AT_CMD 권한 과다($PERMS>750);"
    fi
fi

# [Step 2] at 작업 목록 파일 소유자 및 권한 확인
# 가이드: ls -l /var/spool/at/<파일>, /var/spool/cron/atjobs/<파일> (권한 640 이하)
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for dir in "${AT_SPOOL_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for f in "$dir"/*; do
            if [ -f "$f" ]; then
                OWNER=$(stat -c '%U' "$f" 2>/dev/null)
                PERMS=$(stat -c '%a' "$f" 2>/dev/null)
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f 소유자 root 아님($OWNER);"
                fi
                if check_perm_exceeds "$PERMS" 640; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f 권한 과다($PERMS>640);"
                fi
            fi
        done
    fi
done

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="cron/at 파일 권한 취약:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="crontab/at 명령어 750 이하, 관련 파일 640 이하 적절히 설정됨"
fi

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
    "guide": "crontab 관련 파일 권한을 640 이하, 소유자를 root로 설정하고, cron.allow/deny 파일을 적절히 구성하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
