#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
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
TARGET_FILE=""
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 수동 명령 실행 시 ./를 명시해야 하는 정도의 경미한 사용상 변화만 발생합니다."

# 2. 진단 로직

# root PATH 값 추출
ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)

EVIDENCE+="root PATH=$ROOT_PATH\n"

# 콜론(:) 기준으로 분해
IFS=':' read -ra PATH_ITEMS <<< "$ROOT_PATH"

INDEX=0
for ITEM in "${PATH_ITEMS[@]}"; do
    if [ "$ITEM" = "." ]; then
        if [ "$INDEX" -eq 0 ]; then
            STATUS="FAIL"
            EVIDENCE+="[취약] '.' 이 PATH 맨 앞에 존재\n"
        elif [ "$INDEX" -lt $((${#PATH_ITEMS[@]} - 1)) ]; then
            STATUS="FAIL"
            EVIDENCE+="[취약] '.' 이 PATH 중간에 존재\n"
        else
            EVIDENCE+="[양호] '.' 이 PATH 맨 끝에 존재 (허용)\n"
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
    "guide": "root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 “.”을 PATH 환경변수의 마지막으로 이동하도록 설정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",
    "check_date": "$CHECK_DATE"
}
EOF