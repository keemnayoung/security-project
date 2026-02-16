#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-18"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/shadow"
CHECK_COMMAND='stat -c "%U %a" /etc/shadow'

DETAIL_CONTENT=""
REASON_LINE=""

# 파일 존재 여부에 따른 분기
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/shadow 파일이 존재하지 않아 패스워드 해시 정보 보호와 접근 통제가 보장되지 않으므로 취약합니다. /etc/shadow 파일을 생성(복구)하고 소유자를 root, 권한을 400 이하로 설정해야 합니다."
    DETAIL_CONTENT="file_not_found"
else
    FILE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    FILE_PERM_RAW=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # stat 실패/빈값 방어
    if [ -z "$FILE_OWNER" ] || [ -z "$FILE_PERM_RAW" ]; then
        STATUS="FAIL"
        REASON_LINE="/etc/shadow 파일의 소유자/권한 정보를 확인할 수 없어 점검에 실패했습니다(stat 실행 오류)."
        DETAIL_CONTENT="stat_failed"
    else
        # 권한을 3자리(0-padding)로 정규화하여 자리수 오판 방지
        FILE_PERM=$(printf "%03d" "$FILE_PERM_RAW")
        U_PERM="${FILE_PERM:0:1}"
        G_PERM="${FILE_PERM:1:1}"
        O_PERM="${FILE_PERM:2:1}"

        # '400 이하'를 "소유자: 읽기만(4 또는 0), 그룹/기타: 0"로 해석하여 오판 방지
        # - U_PERM: 4(읽기만) 또는 0(권한 없음) 허용
        # - G_PERM/O_PERM: 반드시 0이어야 함
        PERM_OK=0
        if { [ "$U_PERM" = "4" ] || [ "$U_PERM" = "0" ]; } && [ "$G_PERM" = "0" ] && [ "$O_PERM" = "0" ]; then
            PERM_OK=1
        fi

        # 소유자/권한 기준에 따른 분기
        if [ "$FILE_OWNER" = "root" ] && [ "$PERM_OK" -eq 1 ]; then
            STATUS="PASS"
            REASON_LINE="/etc/shadow 파일의 소유자가 root이고 권한이 $FILE_PERM(400 이하: 그룹/기타 권한 없음)로 설정되어 있으므로 패스워드 해시 정보에 대한 비인가 접근 위험이 없고 이 항목에 대한 보안 위협이 없습니다."
        else
            STATUS="FAIL"
            REASON_LINE="/etc/shadow 파일의 소유자가 $FILE_OWNER 이거나 권한이 $FILE_PERM(기준 미충족)로 설정되어 비인가 사용자가 패스워드 해시 정보를 열람할 위험이 있으므로 취약합니다. 소유자를 root로 변경하고 권한을 400 이하로 설정해야 합니다."
        fi

        # 소유자/권한은 한 줄로 출력
        DETAIL_CONTENT="owner=$FILE_OWNER perm=$FILE_PERM"
    fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
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