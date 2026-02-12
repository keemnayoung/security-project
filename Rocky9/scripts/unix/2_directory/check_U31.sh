#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 1. 항목 정보 정의
ID="U-31"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈디렉토리 소유자 및 권한 설정"
IMPORTANCE="중"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 공용처럼 사용되던 홈 디렉터리 구조가 있었다면 일부 사용자나 스크립트의 접근이 제한되어 업무에 영향을 줄 수 있습니다."
TARGET_FILE="/etc/passwd"
FILE_HASH="$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')


# 2. 진단 로직
# 로그인 가능한 사용자 대상으로 홈 디렉토리 점검
EVIDENCE_LINES=()

while IFS=: read -r USER _ _ _ _ HOME _; do


    # 홈 디렉토리가 실제로 존재하는 경우만 점검
    [[ ! -d "$HOME" ]] && continue

    OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
    PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')
    OTHER_WRITE=$((PERM % 10))

    if [[ "$OWNER" != "$USER" || "$OTHER_WRITE" -ge 2 ]]; then
        if [[ "$OWNER" != "root" ]]; then
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE_LINES+=("${USER}:${HOME}(owner=${OWNER},perm=${PERM})")
        fi
    fi

done < /etc/passwd

if [ "$STATUS" == "PASS" ]; then
    ACTION_RESULT="SUCCESS"
    EVIDENCE="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 모두 적절하게 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    EVIDENCE="홈 디렉토리 소유자가 해당 계정이 아닌 계정 또는 타 사용자 쓰기 권한이 설정된 파일이 발견되었습니다. 보안을 위해 각 계정에 홈 디렉터리 소유자 또는 권한 설정이 필요합니다. "
    EVIDENCE+=$(printf "[")
    EVIDENCE+=$(printf "%s, " "${EVIDENCE_LINES[@]}")
    EVIDENCE+=$(printf "]")
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF

