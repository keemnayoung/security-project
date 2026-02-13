#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값이 022 이상 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.2 (scan_history DB 연동)
# @Author: 권순형
# @Last Updated: 2026-02-12
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : /etc/profile 및 /etc/login.defs 내 UMASK(또는 umask) 값이 022 이상인지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-30"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/profile /etc/login.defs"
CHECK_COMMAND='grep -iE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/profile | tail -n 1; grep -iE "^[[:space:]]*UMASK[[:space:]]+[0-9]+" /etc/login.defs | tail -n 1'

UMASK_PROFILE=""
UMASK_LOGIN_DEFS=""

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_ANY="N"
FOUND_VULN="N"

# /etc/profile 내 umask 설정 확인
if [ -f /etc/profile ]; then
    UMASK_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | awk '{print $2}' | tail -n 1)
fi

# /etc/login.defs 내 UMASK 설정 확인
if [ -f /etc/login.defs ]; then
    UMASK_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | awk '{print $2}' | tail -n 1)
fi

# 값 존재 여부 확인
CHECK_VALUES=()
[ -n "$UMASK_PROFILE" ] && CHECK_VALUES+=("$UMASK_PROFILE") && FOUND_ANY="Y"
[ -n "$UMASK_LOGIN_DEFS" ] && CHECK_VALUES+=("$UMASK_LOGIN_DEFS") && FOUND_ANY="Y"

# UMASK 판단 (022 이상이어야 양호)
if [ "$FOUND_ANY" = "N" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/profile 및 /etc/login.defs 파일에서 UMASK 설정이 확인되지 않아 기본 파일 생성 권한이 과도하게 열릴 수 있으므로 취약합니다. UMASK 값을 022로 설정해야 합니다."
    DETAIL_CONTENT="/etc/profile umask=not_set\n/etc/login.defs UMASK=not_set"
else
    for VALUE in "${CHECK_VALUES[@]}"; do
        if [ "$VALUE" -lt 22 ]; then
            FOUND_VULN="Y"
            break
        fi
    done

    if [ "$FOUND_VULN" = "Y" ]; then
        STATUS="FAIL"
        REASON_LINE="UMASK 값이 022 미만으로 설정되어 새로 생성되는 파일/디렉터리 권한이 과도하게 부여될 수 있으므로 취약합니다. /etc/profile과 /etc/login.defs에 UMASK 값을 022로 설정해야 합니다."
    else
        STATUS="PASS"
        REASON_LINE="UMASK 값이 022 이상으로 설정되어 새로 생성되는 파일/디렉터리 권한이 과도하게 부여되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
    fi

    DETAIL_CONTENT="/etc/profile umask=${UMASK_PROFILE:-not_set}\n/etc/login.defs UMASK=${UMASK_LOGIN_DEFS:-not_set}"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF