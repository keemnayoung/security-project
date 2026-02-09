#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-08
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 그룹(root)에 등록된 불필요한 일반 계정을 제거하여 권한 오남용 방지
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-08"
CATEGORY="계정관리"
TITLE="관리자 그룹에 최소한의 계정 포함"
IMPORTANCE="중"
TARGET_FILE="/etc/group"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 대상 확인 및 백업
if [ -f "$TARGET_FILE" ]; then
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"
    
    # root 그룹 내 root 제외 계정 추출
    EXTRA_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | xargs)

    if [ -z "$EXTRA_USERS" ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="양호: 이미 root 그룹에 불필요한 계정이 없습니다."
    else
        # 2. 계정 제거 수행
        REMOVED_USERS=()
        for user in $EXTRA_USERS; do
            if gpasswd -d "$user" root >/dev/null 2>&1; then
                REMOVED_USERS+=("$user")
            fi
        done

        # 3. [핵심 검증] 조치 후 상태 재확인
        REMAIN_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | wc -l)
        
        if [ "$REMAIN_USERS" -eq 0 ]; then
            ACTION_RESULT="SUCCESS"
            STATUS="PASS"
            ACTION_LOG="조치 완료. root 그룹에서 계정(${REMOVED_USERS[*]}) 제거 완료."
        else
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="조치 실패. 일부 계정이 제거되지 않았습니다. 수동 확인이 필요합니다."
        fi
    fi
else
    ACTION_LOG="오류: 대상 파일($TARGET_FILE)이 없습니다."
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