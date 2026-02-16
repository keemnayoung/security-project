#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-10
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 동일한 UID 금지
# @Description : /etc/passwd 파일 내 중복된 UID가 존재하는지 점검
# @Criteria_Good : 모든 계정의 UID가 고유하게 설정된 경우
# @Criteria_Bad : 하나 이상의 계정이 동일한 UID를 공유하고 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-10"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='[ -f /etc/passwd -a -r /etc/passwd ] && cut -d: -f3 /etc/passwd | sort -n | uniq -d || echo "passwd_not_found_or_not_readable"'

REASON_LINE=""
DETAIL_CONTENT=""

DUPS=""
DUPLICATE_LINES=""

# 파일 존재 여부에 따른 분기
if [ -f "$TARGET_FILE" ]; then
    # (필수 추가) 파일이 존재하지만 읽을 수 없는 경우: 점검 불가이므로 FAIL
    if [ ! -r "$TARGET_FILE" ]; then
        STATUS="FAIL"
        REASON_LINE="사용자 정보 파일(/etc/passwd)이 존재하지만 읽기 권한이 없어 UID 중복 여부를 점검할 수 없으므로 취약합니다. 파일 권한/ACL을 확인하여 점검 가능 상태로 만든 뒤 재점검해야 합니다."
        DETAIL_CONTENT="passwd_not_readable"
    else
        # UID 목록이 비정상적으로 비어있는 경우도 점검 불가로 처리
        UID_LIST="$(cut -d: -f3 "$TARGET_FILE" 2>/dev/null | sed '/^[[:space:]]*$/d')"
        if [ -z "$UID_LIST" ]; then
            STATUS="FAIL"
            REASON_LINE="사용자 정보 파일(/etc/passwd)에서 UID를 추출할 수 없어 점검을 수행할 수 없으므로 취약합니다. 파일 형식 이상 여부를 확인하고 복구 후 재점검해야 합니다."
            DETAIL_CONTENT="passwd_parse_failed"
        else
            # 중복 UID 값 추출
            DUPS=$(printf "%s\n" "$UID_LIST" | sort -n | uniq -d)

            if [ -z "$DUPS" ]; then
                STATUS="PASS"
                REASON_LINE="모든 계정이 고유한 UID를 사용하고 있어 계정 간 권한 충돌 및 추적 혼선 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
                DETAIL_CONTENT="no_duplicate_uids"
            else
                STATUS="FAIL"
                REASON_LINE="동일한 UID를 공유하는 계정이 존재하여 권한 경계가 무너지고 감사 추적이 어려워질 수 있으므로 취약합니다. 중복 계정 중 하나의 UID를 변경하고 해당 UID로 소유된 파일의 소유권도 함께 재설정해야 합니다."

                # 중복 UID별 계정 매칭(반복문)
                for uid in $DUPS; do
                    ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" 2>/dev/null | xargs | sed 's/ /, /g')
                    DUPLICATE_LINES+="uid=$uid accounts=$ACCOUNTS"$'\n'
                done

                DETAIL_CONTENT="$(printf "%s" "$DUPLICATE_LINES" | sed 's/[[:space:]]*$//')"
            fi
        fi
    fi
else
    STATUS="FAIL"
    REASON_LINE="사용자 정보 파일(/etc/passwd)이 존재하지 않아 UID 중복 여부를 점검할 수 없으므로 취약합니다. /etc/passwd 파일을 복구한 뒤 UID 중복 여부를 점검해야 합니다."
    DETAIL_CONTENT="passwd_not_found"
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