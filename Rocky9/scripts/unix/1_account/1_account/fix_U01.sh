#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-01
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : root 계정 원격 접속 제한
# @Description : 원격 터미널 서비스를 통한 root 계정의 직접 접속 제한 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-01"
CATEGORY="계정관리"
TITLE="root 계정 원격 접속 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/ssh/sshd_config"
CONF_DIR="/etc/ssh/sshd_config.d"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then
    # 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"
    
    # [수정] 1) 메인 설정 파일 수정: 기존 설정 삭제 후 확실하게 'no' 삽입
    sed -i '/PermitRootLogin/d' "$TARGET_FILE"
    echo "PermitRootLogin no" >> "$TARGET_FILE"
    
    # [강화] 2) .d 폴더 내의 모든 우선순위 설정 무력화
    if [ -d "$CONF_DIR" ]; then
        # 특정 파일(01-permitrootlogin.conf 등) 삭제
        rm -f "$CONF_DIR/01-permitrootlogin.conf"
        
        # 나머지 모든 .conf 파일에서 PermitRootLogin이 포함된 줄을 삭제 (주석보다 확실함)
        find "$CONF_DIR" -name "*.conf" -exec sed -i '/PermitRootLogin/d' {} + 2>/dev/null
    fi
    
    # 3) 서비스 재시작
    systemctl daemon-reload >/dev/null 2>&1
    if systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; then
        
        # [검증] 실제 런타임 적용값 확인
        FINAL_VAL=$(sshd -T | grep -i "permitrootlogin" | awk '{print $2}')
        
        if [ "$FINAL_VAL" == "no" ]; then
            ACTION_RESULT="SUCCESS"
            STATUS="PASS"
            ACTION_LOG="조치 완료. 모든 설정 파일 정리 및 root 접속 차단 확인 완료. (최종값: $FINAL_VAL)"
            EVIDENCE="최종 적용값: $FINAL_VAL (양호)"
        else
            # 여전히 적용되지 않은 경우
            ACTION_RESULT="PARTIAL_SUCCESS"
            STATUS="FAIL"
            ACTION_LOG="조치 실패. 파일 수정 및 .d 정리를 수행했으나 여전히 '$FINAL_VAL'입니다. 수동 확인이 필요합니다."
            EVIDENCE="최종 적용값: $FINAL_VAL (취약)"
        fi
    else
        # 실패 시 롤백
        mv "$BACKUP_FILE" "$TARGET_FILE"
        systemctl restart sshd >/dev/null 2>&1
        ACTION_RESULT="FAIL_AND_ROLLBACK"
        STATUS="FAIL"
        ACTION_LOG="서비스 재시작 실패로 설정을 원복했습니다."
        EVIDENCE="롤백 완료 (취약)"
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일($TARGET_FILE)이 없습니다."
    EVIDENCE="파일 없음"
fi

# 2. JSON 표준 출력
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