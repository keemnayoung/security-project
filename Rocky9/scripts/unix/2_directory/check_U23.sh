#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.2
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-23
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-23"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/ (root 소유 SUID/SGID/Sticky bit 설정 파일)"
CHECK_COMMAND='find / -user root -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) -xdev 2>/dev/null'

DETAIL_CONTENT=""
REASON_LINE=""

# 1) SUID/SGID가 설정된 root 소유 파일 검색
RESULT_SUID_SGID=$(find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null)

# 2) Sticky bit가 설정된 root 소유 "파일" 검색 (가이드에 Sticky bit 포함)
RESULT_STICKY=$(find / -user root -type f -perm -01000 -xdev 2>/dev/null)

# 결과 유무에 따른 PASS/FAIL 결정
if [ -n "$RESULT_SUID_SGID" ] || [ -n "$RESULT_STICKY" ]; then
    STATUS="FAIL"

    REASON_LINE="root 소유 파일 중 SUID/SGID 또는 Sticky bit가 설정된 파일이 발견되었습니다. 해당 파일이 악용될 경우 권한 상승 및 비인가 행위로 이어질 수 있으므로 취약합니다. 불필요한 특수 권한(SUID/SGID/Sticky)을 제거하거나 해당 파일을 제거해야 합니다."

    # 상세 내용 구성 (항목별로 구분)
    DETAIL_CONTENT=$(cat <<EOF
[SUID/SGID 설정 파일]
${RESULT_SUID_SGID:-none}

[Sticky bit 설정 파일]
${RESULT_STICKY:-none}
EOF
)
else
    STATUS="PASS"
    REASON_LINE="root 소유 파일 중 SUID/SGID 또는 Sticky bit가 설정된 파일이 발견되지 않아 권한 상승 위험이 낮으므로 양호합니다."
    DETAIL_CONTENT="none"
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