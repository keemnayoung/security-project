#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-17"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/rc.d/*/*, /etc/systemd/system/*"
CHECK_COMMAND='(readlink -f /etc/rc.d/*/* 2>/dev/null; readlink -f /etc/systemd/system/* 2>/dev/null) | sort -u | xargs -I{} sh -c '"'"'stat -c "%n owner=%U perm=%A" "{}" 2>/dev/null'"'"''

TARGET_FILES=()
DETAIL_CONTENT=""
REASON_LINE=""

# 점검 대상 파일 목록 수집 (init 방식)
if [ -d /etc/rc.d ]; then
    INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null)
fi

# 점검 대상 파일 목록 수집 (systemd 방식)
if [ -d /etc/systemd/system ]; then
    SYSTEMD_FILES=$(readlink -f /etc/systemd/system/* 2>/dev/null)
fi

ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sed '/^\s*$/d' | sort -u)

# 대상 파일이 없으면 PASS 처리
if [ -z "$ALL_FILES" ]; then
    STATUS="PASS"
    REASON_LINE="점검 대상 시스템 시작 스크립트 파일이 존재하지 않아 권한 오설정으로 인한 보안 위협이 발생하지 않으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="no_target_files"
else
    VULN_LINES=""
    FOUND_VULN="N"

    # 파일 목록을 순회하며 소유자(root) 및 others-w 여부 점검
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        PERM=$(stat -c %A "$FILE" 2>/dev/null)
        OTHERS_WRITE=$(echo "$PERM" | cut -c9)

        TARGET_FILES+=("$FILE")

        if [ "$OWNER" != "root" ] || [ "$OTHERS_WRITE" = "w" ]; then
            FOUND_VULN="Y"
            STATUS="FAIL"
            VULN_LINES+="$FILE owner=$OWNER perm=$PERM"$'\n'
        fi
    done

    TARGET_FILE=$(printf "%s " "${TARGET_FILES[@]}" | sed 's/[[:space:]]*$//')

    # 취약/양호에 따른 평가 이유와 detail 구성
    if [ "$FOUND_VULN" = "Y" ]; then
        REASON_LINE="시스템 시작 스크립트 파일의 소유자가 root가 아니거나 others 쓰기 권한이 허용되어 있어 임의 수정 및 권한 상승 위험이 있으므로 취약합니다. 소유자를 root(또는 적절한 계정)로 변경하고 others 쓰기 권한(o-w)을 제거해야 합니다."
        DETAIL_CONTENT="$VULN_LINES"
    else
        STATUS="PASS"
        REASON_LINE="시스템 시작 스크립트 파일의 소유자가 root로 설정되어 있고 others 쓰기 권한이 제거되어 있어 임의 수정 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="all_files_ok"
    fi
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