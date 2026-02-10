#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : pwconv 명령어를 사용하여 쉐도우 패스워드 정책을 강제 적용
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-04"
CATEGORY="계정관리"
TITLE="비밀번호 파일 보호"
IMPORTANCE="상"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 백업 (passwd와 shadow 모두 백업)
[ -f /etc/passwd ] && cp -p /etc/passwd /etc/passwd_bak_$TIMESTAMP
[ -f /etc/shadow ] && cp -p /etc/shadow /etc/shadow_bak_$TIMESTAMP

# 2. pwconv 실행 (쉐도우 패스워드 정책 적용)
if command -v pwconv >/dev/null 2>&1; then
    pwconv
    
    # 3. [검증] 조치 후 실제 /etc/passwd 파일 확인
    CHECK_COUNT=$(awk -F: '$2 != "x" {print $1}' /etc/passwd | wc -l)
    
    if [ "$CHECK_COUNT" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
       ACTION_LOG="쉐도우 패스워드 정책을 일괄 적용하고 모든 계정의 비밀번호가 안전하게 암호화되어 관리되도록 조치를 완료하였습니다."
    else
        ACTION_RESULT="FAIL"
        STATUS="FAIL"
        ACTION_LOG="패스워드 암호화 정책을 적용하였으나 일부 계정(${CHECK_COUNT}개)이 여전히 미적용 상태로 남아 있어 추가적인 조치가 필요합니다."
    fi
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="시스템 내에 패스워드 암호화 도구(pwconv)가 존재하지 않아 정책 적용을 완료하지 못했습니다. 수동 점검이 필요합니다."
fi

# 4. 표준 JSON 출력
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