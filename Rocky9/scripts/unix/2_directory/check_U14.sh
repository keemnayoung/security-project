#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 1. 항목 정보 정의
ID="U-14"
CATEGORY="파일 및 디렉토리 관리"
TITLE="root 홈, 패스 디렉터리 권한 및 패스 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE="N/A"
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 '.'을 PATH 환경변수의 마지막으로 이동하도록 설정하십시오."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 수동 명령 실행 시 ./를 명시해야 하는 정도의 경미한 사용상 변화만 발생합니다."
TARGET_FILE="N/A"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"


# 2. 진단 로직

# root PATH 값 추출
ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)

# 콜론(:) 기준으로 분해
IFS=':' read -ra PATH_ITEMS <<< "$ROOT_PATH"

INDEX=0
for ITEM in "${PATH_ITEMS[@]}"; do
    if [ "$ITEM" = "." ]; then
        if [ "$INDEX" -eq 0 ]; then
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE="'.' 이 PATH 맨 앞에 존재합니다. 보안을 위한 PATH 수동 재설정이 필요합니다. "
            EVIDENCE+="현재 root PATH=$ROOT_PATH"
        elif [ "$INDEX" -lt $((${#PATH_ITEMS[@]} - 1)) ]; then
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE="'.' 이 PATH 중간에 존재합니다. 보안을 위한 PATH 수동 재설정이 필요합니다. "
            EVIDENCE+="현재 PATH=$ROOT_PATH"
        else
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            EVIDENCE="root 계정의 PATH 설정이 KISA 보안 가이드라인을 준수하고 있습니다."
            GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
        fi
    fi
    INDEX=$((INDEX + 1))
done


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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF