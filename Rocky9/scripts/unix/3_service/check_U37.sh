#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 적절성 여부 점검
# @Criteria_Good : crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우
# @Criteria_Bad :  crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-37 crontab 설정파일 권한 설정 미흡

# 1. 항목 정보 정의
ID="U-37"
CATEGORY="서비스 관리"
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
        EVIDENCE="$EVIDENCE $CRONTAB_CMD의 소유자가 root가 아닙니다(현재: $OWNER)."
    fi
    if check_perm_exceeds "$PERMS" 750; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $CRONTAB_CMD의 권한이 과대합니다(현재: $PERMS)."
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
                    EVIDENCE="$EVIDENCE $f의 소유자가 root가 아닙니다(현재: $OWNER)."
                fi
                if check_perm_exceeds "$PERMS" 640; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f의 권한이 과대합니다(현재: $PERMS)."
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
            EVIDENCE="$EVIDENCE $f의 소유자가 root가 아닙니다(현재: $OWNER)."
        fi
        if [ -d "$f" ]; then
            # 디렉토리는 750 이하
            if check_perm_exceeds "$PERMS" 750; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $f의 권한이 과대합니다(현재: $PERMS)."
            fi
        else
            # 파일은 640 이하
            if check_perm_exceeds "$PERMS" 640; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $f의 권한이 과대합니다(현재: $PERMS)."
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
        EVIDENCE="$EVIDENCE $AT_CMD의 소유자가 root가 아닙니다(현재: $OWNER)."
    fi
    if check_perm_exceeds "$PERMS" 750; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $AT_CMD의 권한이 과대합니다(현재: $PERMS)."
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
                    EVIDENCE="$EVIDENCE $f의 소유자가 root가 아닙니다(현재: $OWNER)."
                fi
                if check_perm_exceeds "$PERMS" 640; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $f의 권한이 과대합니다(현재: $PERMS)."
                fi
            fi
        done
    fi
done

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="cron/at 관련 파일의 권한이 과도하게 설정되어 있어, 비인가 사용자가 예약 작업을 조작할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="crontab/at 명령어 750 이하, 관련 파일 640 이하 적절히 설정되어 있습니다."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 조치 이후에는 crontab/at 관련 파일 접근 및 예약 작업 등록이 권한 정책에 따라 제한될 수 있으므로 기존에 일반 사용자가 예약 작업을 운영하던 환경이라면 운영 주체와 권한 체계를 재정의해야 합니다."

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
    "guide": "crontab 관련 파일 권한을 640 이하, 소유자를 root로 설정하고, cron.allow/deny 파일을 적절히 구성해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
