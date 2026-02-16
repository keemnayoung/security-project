#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

# 기본 변수
ID="U-16"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='stat -c "%U %a" /etc/passwd'

DETAIL_CONTENT=""
REASON_LINE=""

# 파일 존재 여부에 따른 분기
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/passwd 파일이 존재하지 않아 계정 정보 파일의 무결성과 접근 통제가 보장되지 않으므로 취약합니다. /etc/passwd 파일을 생성(복구)하고 소유자를 root, 권한을 644 이하로 설정해야 합니다."
    DETAIL_CONTENT="file_not_found"
else
    FILE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    FILE_PERM_STR=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # 권한값 파싱 실패 시(예: stat 오류) 방어
    if ! echo "$FILE_PERM_STR" | grep -Eq '^[0-7]{3,4}$'; then
        STATUS="FAIL"
        REASON_LINE="권한 정보를 정상적으로 확인할 수 없어 취약으로 판단합니다. (perm=$FILE_PERM_STR)"
        DETAIL_CONTENT="owner=$FILE_OWNER perm=$FILE_PERM_STR"
    else
        # 8진수 권한을 정수로 변환 (예: "644" -> 420)
        FILE_PERM_DEC=$((8#$FILE_PERM_STR))

        # 기준(필수):
        # 1) 소유자 root
        # 2) 그룹/기타 쓰기 권한 없어야 함 (g+w, o+w 금지)
        # 3) 특수권한(SETUID/SETGID/Sticky) 없어야 함
        OWNER_OK=0
        WRITE_OK=0
        SPECIAL_OK=0

        [ "$FILE_OWNER" = "root" ] && OWNER_OK=1
        # 022 = g+w(020) + o+w(002)
        [ $((FILE_PERM_DEC & 022)) -eq 0 ] && WRITE_OK=1
        # 07000 = setuid(04000) + setgid(02000) + sticky(01000)
        [ $((FILE_PERM_DEC & 07000)) -eq 0 ] && SPECIAL_OK=1

        if [ "$OWNER_OK" -eq 1 ] && [ "$WRITE_OK" -eq 1 ] && [ "$SPECIAL_OK" -eq 1 ]; then
            STATUS="PASS"
            REASON_LINE="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하(그룹/기타 쓰기 및 특수권한 없음)로 설정되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
        else
            STATUS="FAIL"
            REASON_LINE="/etc/passwd 파일의 소유자/권한 설정이 기준에 부합하지 않아 비인가 사용자가 파일을 변경하거나 과도하게 접근할 위험이 있으므로 취약합니다. 소유자를 root로 변경하고 권한을 644 이하로 설정해야 합니다."
        fi

        DETAIL_CONTENT="owner=$FILE_OWNER perm=$FILE_PERM_STR (owner_ok=$OWNER_OK write_ok=$WRITE_OK special_ok=$SPECIAL_OK)"
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

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
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