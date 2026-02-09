#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 내부 정책에 따른 시스템 로깅 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-66"
CATEGORY="로그 관리"
TITLE="정책에 따른 시스템 로깅 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/rsyslog.conf /etc/rsyslog.d/default.conf"
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="내부 정책에 따라 시스템 로깅 설정을 적용하면 보안 감사와 사고 분석에 필요한 로그가 안정적으로 수집되는 대신, 로그 저장 공간 사용량이 증가하고 고부하 환경에서는 디스크 I/O가 소폭 증가할 수 있습니다."
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")


# 2. 진단 로직
STATUS="PASS"
EVIDENCE=""

REQUIRED_POLICIES=(
    "*.info;mail.none;authpriv.none;cron.none /var/log/messages"
    "auth,authpriv.* /var/log/secure"
    "mail.* /var/log/maillog"
    "cron.* /var/log/cron"
    "*.alert /dev/console"
    "*.emerg *"
)

CONFIG_FOUND=false
POLICY_OK=true

for FILE in /etc/rsyslog.conf /etc/rsyslog.d/default.conf; do
    if [ -f "$FILE" ]; then
        CONFIG_FOUND=true
        for POLICY in "${REQUIRED_POLICIES[@]}"; do
            if ! grep -E "^[[:space:]]*${POLICY//\*/\\*}" "$FILE" >/dev/null 2>&1; then
                POLICY_OK=false
                EVIDENCE+="[누락] $POLICY (파일: $FILE)\n"
            fi
        done
    fi
done

if [ "$CONFIG_FOUND" = false ]; then
    STATUS="FAIL"
    EVIDENCE="rsyslog 설정 파일이 존재하지 않음"
elif [ "$POLICY_OK" = false ]; then
    STATUS="FAIL"
fi

# 로그 파일 존재 여부 추가 확인
LOG_FILES=(
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/maillog"
    "/var/log/cron"
)

for LOG in "${LOG_FILES[@]}"; do
    if [ ! -f "$LOG" ]; then
        STATUS="FAIL"
        EVIDENCE+="[로그 미존재] $LOG\n"
    fi
done

[ -z "$EVIDENCE" ] && EVIDENCE="내부 정책에 따른 로그 기록 정책이 정상적으로 설정 및 적용되어 있음"


# 3. 마스터 JSON 출력
echo ""

cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo -e "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')",
    "guide": "/etc/rsyslog.conf 또는 /etc/rsyslog.d/default.conf 파일 내에 로그 기록 정책을 수립해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF