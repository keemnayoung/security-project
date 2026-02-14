#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-20"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# [추가] xinetd.d 및 system.conf 명시 포함
TARGET_FILE="/etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/* /etc/systemd/system.conf /etc/systemd/*"
CHECK_COMMAND='stat -c "%U %a %n" /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf 2>/dev/null; find /etc/xinetd.d -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%U %a %n" "{}" 2>/dev/null; find /etc/systemd -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%U %a %n" "{}" 2>/dev/null'

DETAIL_CONTENT=""
REASON_LINE=""
VULN_LINES=""

# 단일 파일 점검 함수
check_file() {
    local FILE="$1"

    # 파일이 없으면 detail에 INFO로 남김
    if [ ! -e "$FILE" ]; then
        DETAIL_CONTENT+="[INFO] $FILE file_not_found"$'\n'
        return
    fi

    local OWNER
    local PERM
    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %a "$FILE" 2>/dev/null)

    # 취약이면 목록 누적
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        STATUS="FAIL"
        VULN_LINES+="$FILE owner=$OWNER perm=$PERM"$'\n'
    fi
}

# 디렉터리 내 파일 점검 함수
check_directory_files() {
    local DIR="$1"

    # 디렉터리가 없으면 detail에 INFO로 남김
    if [ ! -d "$DIR" ]; then
        DETAIL_CONTENT+="[INFO] $DIR dir_not_found"$'\n'
        return
    fi

    # 디렉터리 내 파일 순회
    while IFS= read -r FILE; do
        local OWNER
        local PERM
        OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        PERM=$(stat -c %a "$FILE" 2>/dev/null)

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
            STATUS="FAIL"
            VULN_LINES+="$FILE owner=$OWNER perm=$PERM"$'\n'
        fi
    done < <(find "$DIR" -type f 2>/dev/null)
}

# inetd / xinetd 설정 파일 점검
check_file "/etc/inetd.conf"
check_file "/etc/xinetd.conf"

# [추가] xinetd.d 디렉터리 내 모든 파일 점검 (가이드 Step 2)
check_directory_files "/etc/xinetd.d"

# systemd 설정 파일 및 디렉터리 점검
check_directory_files "/etc/systemd"

# 결과에 따른 평가 이유 및 detail 구성
if [ "$STATUS" = "PASS" ]; then
    REASON_LINE="/etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d 및 /etc/systemd 내 파일의 소유자가 root이고 권한이 600 이하로 설정되어 있어 비인가 사용자의 임의 수정이 제한되므로 이 항목에 대한 보안 위협이 없습니다."
    if [ -z "$DETAIL_CONTENT" ]; then
        DETAIL_CONTENT="all_files_ok"
    else
        # INFO만 있는 경우(파일/디렉터리 미존재 정보)는 유지
        DETAIL_CONTENT="$(printf "%s" "$DETAIL_CONTENT" | sed 's/[[:space:]]*$//')"
    fi
else
    REASON_LINE="/etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d 또는 /etc/systemd 내 일부 파일의 소유자가 root가 아니거나 권한이 600 초과로 설정되어 비인가 사용자가 설정을 변경할 위험이 있으므로 취약합니다. 해당 파일들의 소유자를 root로 변경하고 권한을 600 이하로 설정해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
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