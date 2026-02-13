#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 권순형
# @Last Updated: 2026-02-12
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 기본 변수
ID="U-15"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/"
CHECK_COMMAND='find / -xdev \( -nouser -o -nogroup \) 2>/dev/null'

# 고아 파일/디렉터리 목록 수집
ORPHAN_FILES_RAW=$(find / \
    -xdev \
    \( -nouser -o -nogroup \) \
    2>/dev/null)

# 결과 유무에 따른 PASS/FAIL 결정
if [ -n "$ORPHAN_FILES_RAW" ]; then
    STATUS="FAIL"
    REASON_LINE="소유자 또는 그룹이 존재하지 않는 파일/디렉터리가 발견되어 관리 주체가 불명확하고 접근 통제가 어려우므로 취약합니다. 해당 파일/디렉터리를 제거하거나 적절한 소유자 및 그룹으로 변경해야 합니다."
    DETAIL_CONTENT="$ORPHAN_FILES_RAW"
else
    STATUS="PASS"
    REASON_LINE="소유자 또는 그룹이 존재하지 않는 파일/디렉터리가 발견되지 않아 관리 주체가 명확하며 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="none"
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