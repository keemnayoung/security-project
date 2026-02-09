#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-20"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
EVIDENCE=""
ACTION_LOG=""

FILES=(
    "/etc/inetd.conf"
    "/etc/xinetd.conf"
    "/etc/systemd/system.conf"
)

DIR="/etc/systemd"

# 1. 실제 조치 프로세스 시작
ERROR_FLAG=0

fix_file() {
    local FILE="$1"

    if [ ! -f "$FILE" ]; then
        ACTION_LOG+="[$FILE 없음] "
        return
    fi

    chown root "$FILE" 2>/dev/null
    chmod 600 "$FILE" 2>/dev/null

    OWNER=$(stat -c %U "$FILE")
    PERM=$(stat -c %a "$FILE")

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        ERROR_FLAG=1
        ACTION_LOG+="[$FILE 조치 실패] "
    else
        ACTION_LOG+="[$FILE 조치 완료] "
    fi
}

# 개별 파일 조치
for FILE in "${FILES[@]}"; do
    fix_file "$FILE"
done

# systemd 디렉터리 내 파일 조치
if [ -d "$DIR" ]; then
    while IFS= read -r FILE; do
        chown root "$FILE" 2>/dev/null
        chmod 600 "$FILE" 2>/dev/null

        OWNER=$(stat -c %U "$FILE")
        PERM=$(stat -c %a "$FILE")

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
            ERROR_FLAG=1
        fi
    done < <(find "$DIR" -type f 2>/dev/null)
else
    ACTION_LOG+="[/etc/systemd 없음] "
fi


# 2. 최종 판정
if [ "$ERROR_FLAG" -eq 0 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="모든 대상 파일의 소유자가 root이며 권한이 600 이하로 설정됨 (양호)"
    ACTION_LOG+="최종 확인 완료"
else
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="일부 파일의 소유자 또는 권한이 기준에 부합하지 않음 (취약)"
    ACTION_LOG+="일부 항목 수동 확인 필요"
fi


# 3. JSON 표준 출력
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