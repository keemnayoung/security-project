#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ===============================================  =============================

# 기본 변수
ID="U-29"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/hosts.lpd"
CHECK_COMMAND='[ -e /etc/hosts.lpd ] && stat -c "%F|%U|%a" /etc/hosts.lpd || echo "file_not_found"'

DETAIL_CONTENT=""
REASON_LINE=""

# 파일 존재 여부에 따른 분기
if [ ! -e "$TARGET_FILE" ]; then
    STATUS="PASS"
    REASON_LINE="/etc/hosts.lpd 파일이 존재하지 않아 레거시 출력 서비스 기반 접근 허용 설정이 적용되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="file_not_found"
else
    # [추가] 파일 타입 확인(일반 파일이 아닌 경우 FAIL 처리)
    FILE_TYPE=$(stat -c %F "$TARGET_FILE" 2>/dev/null)
    if [ -z "$FILE_TYPE" ]; then
        STATUS="FAIL"
        REASON_LINE="/etc/hosts.lpd 파일은 존재하나 파일 정보 조회(stat) 실패로 소유자/권한을 확인할 수 없어 취약 여부 판단이 불가능합니다. 수동 확인이 필요합니다."
        DETAIL_CONTENT="stat_failed"
    elif [ "$FILE_TYPE" != "regular file" ]; then
        STATUS="FAIL"
        REASON_LINE="/etc/hosts.lpd 경로가 일반 파일이 아닌 형태($FILE_TYPE)로 존재하여 권한/소유자 관리 기준을 충족한다고 볼 수 없으므로 취약합니다. 비정상 타입(링크/디렉터리 등) 제거 및 정상 파일 여부를 확인해야 합니다."
        DETAIL_CONTENT="type=$FILE_TYPE"
    else
        OWNER=$(stat -c %U "$TARGET_FILE" 2>/dev/null)
        PERM=$(stat -c %a "$TARGET_FILE" 2>/dev/null)

        # [추가] 소유자/권한 값 조회 실패 처리
        if [ -z "$OWNER" ] || [ -z "$PERM" ] || ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
            STATUS="FAIL"
            REASON_LINE="/etc/hosts.lpd 파일은 존재하나 소유자/권한 값 조회에 실패하여 취약 여부 판단이 불가능합니다. 수동 확인이 필요합니다."
            DETAIL_CONTENT="owner=$OWNER perm=$PERM"
        else
            # 소유자/권한 기준에 따른 분기
            if [ "$OWNER" = "root" ] && [ "$PERM" -le 600 ]; then
                STATUS="PASS"
                REASON_LINE="/etc/hosts.lpd 파일의 소유자가 root이고 권한이 $PERM(600 이하)로 제한되어 비인가 사용자의 임의 수정 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
            else
                STATUS="FAIL"
                REASON_LINE="/etc/hosts.lpd 파일의 소유자가 $OWNER 이거나 권한이 $PERM(600 초과)로 설정되어 비인가 사용자가 접근 허용 정보를 변조할 위험이 있으므로 취약합니다. 파일을 제거하거나 소유자를 root로 변경하고 권한을 600 이하로 설정해야 합니다."
            fi

            DETAIL_CONTENT="type=$FILE_TYPE owner=$OWNER perm=$PERM"
        fi
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