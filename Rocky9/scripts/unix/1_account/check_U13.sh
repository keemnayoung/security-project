#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 저장 시 SHA-512와 같은 안전한 암호화 알고리즘 사용 여부 점검
# @Criteria_Good : 암호화 알고리즘이 SHA-512로 설정되어 있고 기존 계정들도 적용된 경우
# @Criteria_Bad : 암호화 알고리즘이 MD5 등 취약한 알고리즘이거나 설정이 미비한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-13"
CATEGORY="계정관리"
TITLE="안전한 비밀번호 암호화 알고리즘 사용"
IMPORTANCE="중"
DEFS_FILE="/etc/login.defs"
SHADOW_FILE="/etc/shadow"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="암호화 알고리즘 변경 설정(SHA-512 등)은 일반적인 시스템 운영에는 영향이 없습니다. 다만, 설정 변경 이후 생성되는 계정이나 비밀번호를 새로 변경하는 계정에만 적용되므로, 기존 계정들은 다음 비밀번호 변경 주기 전까지 이전 알고리즘으로 유지됨을 유의해야 합니다."

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$DEFS_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    # 1. 파일 해시 추출
    FILE_HASH=$(sha256sum "$DEFS_FILE" | awk '{print $1}')
    
    # 2. /etc/login.defs 설정 확인
    ENCRYPT_METHOD=$(grep -i "^ENCRYPT_METHOD" "$DEFS_FILE" | awk '{print $2}')
    
    # 3. [검증 강화] /etc/shadow에서 실제 사용 중인 알고리즘 식별자 확인 ($6$ = SHA-512)
    # 암호가 설정된 계정 중 SHA-512가 아닌 계정이 있는지 확인
    INVALID_ALGO_ACCOUNTS=$(awk -F: '$2 ~ /^\$/ && $2 !~ /^\$6\$/ {print $1}' "$SHADOW_FILE" | xargs | sed 's/ /, /g')
    
    if [[ "$ENCRYPT_METHOD" =~ "SHA512" ]]; then
        if [ -z "$INVALID_ALGO_ACCOUNTS" ]; then
            STATUS="PASS"
            EVIDENCE="ENCRYPT_METHOD가 SHA512이며, 모든 계정이 안전한 알고리즘을 사용 중입니다."
        else
            STATUS="FAIL"
            EVIDENCE="설정은 SHA512이나, 기존 일부 계정이 취약한 알고리즘 사용 중입니다. ($INVALID_ALGO_ACCOUNTS)"
        fi
    else
        STATUS="FAIL"
        EVIDENCE="취약한 암호화 알고리즘을 사용 중입니다. (현재 설정: $ENCRYPT_METHOD)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="필수 설정 파일이 누락되었습니다."
    FILE_HASH="NOT_FOUND"
fi

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
    "guide": "/etc/login.defs 파일에서 ENCRYPT_METHOD를 SHA512로 설정하세요.",
    "file_hash": "$FILE_HASH",
    "target_file": "$DEFS_FILE,$SHADOW_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF