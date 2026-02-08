#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
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
TARGET_FILE="/etc/ssh/sshd_config"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"

# root 계정의 로그인 PATH 환경변수 획득
ROOT_PATH=$(su - root -c "echo \$PATH" 2>/dev/null)

# PATH를 ':' 기준으로 배열로 분리
IFS=':' read -r -a PATH_ARRAY <<< "$ROOT_PATH"
PATH_COUNT=${#PATH_ARRAY[@]}

# PATH 내 '.' 위치 점검
for (( i=0; i<PATH_COUNT; i++ )); do
    if [ "${PATH_ARRAY[$i]}" = "." ]; then
        if [ "$i" -ne $((PATH_COUNT - 1)) ]; then
            STATUS="FAIL"
            break
        fi
    fi
done

if [ "$STATUS" = "FAIL" ]; then
    EVIDENCE="root PATH에 '.'이 맨 앞 또는 중간에 포함됨 → $ROOT_PATH"
else
    EVIDENCE="root PATH에 '.'이 맨 마지막이거나 포함되지 않음"
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
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF