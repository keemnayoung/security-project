#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-08
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 그룹(root)에 불필요한 일반 계정이 포함되어 있는지 점검
# @Criteria_Good : 관리자 그룹에 root 계정만 포함되어 있는 경우
# @Criteria_Bad : 관리자 그룹에 root 이외의 일반 계정이 포함되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-08"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"

CHECK_COMMAND='[ -f /etc/group ] && (grep -E "^root:x:0:" /etc/group || echo "root_group_line_not_found") || echo "group_file_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

ROOT_GROUP_USERS=""
EXTRA_USERS=""
PRIMARY_GID0_USERS=""

# 파일 존재 여부에 따른 분기
if [ -f "$TARGET_FILE" ]; then
    # root 그룹 사용자 필드 추출
    ROOT_GROUP_USERS=$(grep -E '^root:x:0:' "$TARGET_FILE" 2>/dev/null | cut -d: -f4 | tail -n 1)

    # root 제외 사용자만 추출 (쉼표 구분 → 라인 구분 → root/빈값 제거)
    EXTRA_USERS=$(echo "$ROOT_GROUP_USERS" \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^root$' \
        | grep -v '^$' )

    # (필수 추가) /etc/passwd에서 주 그룹(GID)이 0인 계정(root 제외) 점검
    if [ -f "$PASSWD_FILE" ]; then
        PRIMARY_GID0_USERS=$(awk -F: '($4==0 && $1!="root"){print $1}' "$PASSWD_FILE" 2>/dev/null)
    else
        PRIMARY_GID0_USERS="passwd_file_not_found"
    fi

    # 취약 여부 판단: 보조 그룹(root 라인) + 주 그룹(GID 0) 중 하나라도 불필요 계정 존재 시 FAIL
    if [ -z "$EXTRA_USERS" ] && [ -z "$PRIMARY_GID0_USERS" ]; then
        STATUS="PASS"
        REASON_LINE="root 그룹(GID 0)에 root 이외 사용자가 포함되어 있지 않아 관리자 권한이 불필요하게 부여되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
        if [ -n "$ROOT_GROUP_USERS" ]; then
            DETAIL_CONTENT="root_group_members=$ROOT_GROUP_USERS"
        else
            DETAIL_CONTENT="root_group_members=empty"
        fi
    else
        STATUS="FAIL"
        REASON_LINE="root 그룹(GID 0)에 불필요 계정이 포함되어 관리자 권한 오남용 및 추적 곤란 위험이 있으므로 취약합니다. /etc/group 및 /etc/passwd에서 root 그룹(GID 0) 관련 불필요 계정을 제거해야 합니다."

        DETAIL_CONTENT=""

        # /etc/group (보조 그룹)에서 발견된 불필요 계정
        if [ -n "$EXTRA_USERS" ]; then
            DETAIL_CONTENT+="root_group_extra_members:"$'\n'"$EXTRA_USERS"
        fi

        # /etc/passwd (주 그룹)에서 발견된 GID 0 계정
        if [ -n "$PRIMARY_GID0_USERS" ]; then
            if [ -n "$DETAIL_CONTENT" ]; then
                DETAIL_CONTENT+=$'\n'
            fi
            DETAIL_CONTENT+="primary_gid0_users:"$'\n'"$PRIMARY_GID0_USERS"
        fi
    fi
else
    STATUS="FAIL"
    REASON_LINE="그룹 정보 파일(/etc/group)이 존재하지 않아 root 그룹(GID 0) 구성원을 점검할 수 없으므로 취약합니다. /etc/group 파일을 복구한 뒤 root 그룹에 불필요 계정이 포함되어 있는지 점검해야 합니다."
    DETAIL_CONTENT="group_file_not_found"
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