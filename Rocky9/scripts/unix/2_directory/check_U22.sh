#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.2
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-22"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/services"
CHECK_COMMAND='[ -f /etc/services ] && stat -c "%U %a" /etc/services 2>/dev/null || echo "services_not_found_or_stat_failed"'

DETAIL_CONTENT=""
REASON_LINE=""

# 파일 존재 여부에 따른 분기
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/services 파일이 존재하지 않아 서비스-포트 매핑 정보의 무결성과 관리가 보장되지 않으므로 취약합니다. /etc/services 파일을 생성(복구)하고 소유자를 root(또는 bin/sys), 권한을 644 이하로 설정해야 합니다."
    DETAIL_CONTENT="file_not_found"
else
    FILE_OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
    FILE_PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

    # stat 실패(권한 문제 등) 처리
    if [ -z "$FILE_OWNER" ] || [ -z "$FILE_PERM" ]; then
        STATUS="FAIL"
        REASON_LINE="/etc/services 파일의 소유자/권한 정보를 확인할 수 없어(예: stat 실패) 현재 설정의 적절성을 검증할 수 없으므로 취약으로 판단합니다. 파일 접근 권한 및 파일 상태를 확인한 뒤 소유자를 root(또는 bin/sys), 권한을 644 이하로 설정해야 합니다."
        DETAIL_CONTENT="stat_failed_or_no_output"
    else
        # 소유자/권한 기준에 따른 분기 (소유자: root|bin|sys, 권한: 644 이하)
        if [[ "$FILE_OWNER" =~ ^(root|bin|sys)$ ]] && [ "$FILE_PERM" -le 644 ]; then
            STATUS="PASS"
            REASON_LINE="/etc/services 파일의 소유자가 $FILE_OWNER(root/bin/sys 허용)이고 권한이 $FILE_PERM(644 이하)로 제한되어 비인가 사용자의 임의 수정 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
        else
            STATUS="FAIL"
            REASON_LINE="/etc/services 파일의 소유자가 $FILE_OWNER(root/bin/sys 외) 이거나 권한이 $FILE_PERM(644 초과)로 설정되어 비인가 사용자가 서비스-포트 매핑 정보를 변경할 위험이 있으므로 취약합니다. 소유자를 root(또는 bin/sys)로 변경하고 권한을 644 이하로 설정해야 합니다."
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