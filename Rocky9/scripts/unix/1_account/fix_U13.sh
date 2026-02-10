#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 암호화 알고리즘을 강력한 SHA512로 설정하여 보안 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
ID="U-13"
CATEGORY="계정관리"
TITLE="안전한 비밀번호 암호화 알고리즘 사용"
IMPORTANCE="중"
DEFS_FILE="/etc/login.defs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"

if [ -f "$DEFS_FILE" ]; then
    # 1. 백업 생성
    cp -p "$DEFS_FILE" "${DEFS_FILE}_bak_$TIMESTAMP"

    # 2. ENCRYPT_METHOD를 SHA512로 변경
    if grep -q "^ENCRYPT_METHOD" "$DEFS_FILE"; then
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' "$DEFS_FILE"
    else
        echo "ENCRYPT_METHOD SHA512" >> "$DEFS_FILE"
    fi

    # 3. [핵심 검증] 조치 후 실제 반영 값 확인
    RESULT_VAL=$(grep "^ENCRYPT_METHOD" "$DEFS_FILE" | awk '{print $2}')
    if [ "$RESULT_VAL" == "SHA512" ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="시스템 패스워드 보안 강화를 위해 암호화 알고리즘을 SHA-512로 변경하고 조치를 완료하였습니다. (기존 계정은 비밀번호 재설정 시 해당 알고리즘이 적용됩니다.)"
    else
        ACTION_LOG="암호화 정책 수정을 시도하였으나 설정 파일에 정상적으로 반영되지 않아 조치가 완료되지 않았습니다. 수동 점검이 필요합니다."
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="암호화 정책 설정 파일($DEFS_FILE)이 식별되지 않아 자동 조치 프로세스를 완료할 수 없습니다."
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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF