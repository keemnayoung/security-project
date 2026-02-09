#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 로그 기록 정책을 보안 정책에 따라 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# ===== U-66 내부 정책 로그 설정 =====
# *.info;mail.none;authpriv.none;cron.none    /var/log/messages
# auth,authpriv.*                             /var/log/secure
# mail.*                                     /var/log/maillog
# cron.*                                     /var/log/cron
# *.alert                                    /dev/console
# *.emerg                                    *
# ===== END U-66 =====

# 0. 기본 변수 정의
ID="U-66"
CATEGORY="로그 관리"
TITLE="정책에 따른 시스템 로깅 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/rsyslog.conf"
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 1. 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then

    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 기존 정책 중복 방지
    sed -i '/U-66 내부 정책 로그 설정/,/END U-66/d' "$TARGET_FILE"

    # 내부 정책 로그 설정 적용
    cat <<EOF >> "$TARGET_FILE"

# ===== U-66 내부 정책 로그 설정 =====
*.info;mail.none;authpriv.none;cron.none    /var/log/messages
auth,authpriv.*                             /var/log/secure
mail.*                                     /var/log/maillog
cron.*                                     /var/log/cron
*.alert                                    /dev/console
*.emerg                                    *
# ===== END U-66 =====
EOF

    # 서비스 재시작
    if systemctl restart rsyslog >/dev/null 2>&1; then

        # 로그 파일 생성 여부 검증
        MISSING_LOGS=()
        for LOG in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do
            [ ! -f "$LOG" ] && MISSING_LOGS+=("$LOG")
        done

        if [ ${#MISSING_LOGS[@]} -eq 0 ]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="내부 정책 로그 설정 적용 및 rsyslog 재시작 완료"
            EVIDENCE="필수 로그 파일 정상 생성 확인 (양호)"
        else
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="설정은 적용되었으나 일부 로그 파일이 생성되지 않음"
            EVIDENCE="미생성 로그 파일: $(IFS=,; echo "${MISSING_LOGS[*]}")"
        fi
    else
        mv "$BACKUP_FILE" "$TARGET_FILE"
        systemctl restart rsyslog >/dev/null 2>&1
        STATUS="FAIL"
        ACTION_RESULT="FAIL_AND_ROLLBACK"
        ACTION_LOG="rsyslog 재시작 실패로 설정 롤백 수행"
        EVIDENCE="롤백 완료 (취약)"
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="조치 대상 파일($TARGET_FILE)이 존재하지 않음"
    EVIDENCE="설정 파일 없음"
fi

# 2. JSON 표준 출력
echo ""

cat <<EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 로그 정책 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF