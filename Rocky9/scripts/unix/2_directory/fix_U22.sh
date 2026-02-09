#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-22"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/services 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/services"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="FAIL"
EVIDENCE="N/A"

# 1. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then


    # 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 소유자 및 권한 조치
    chown root "$TARGET_FILE" 2>/dev/null
    chmod 644 "$TARGET_FILE" 2>/dev/null

    # 조치 후 상태 확인
    AFTER_OWNER=$(stat -c %U "$TARGET_FILE")
    AFTER_PERM=$(stat -c %a "$TARGET_FILE")

    if [[ "$AFTER_OWNER" == "root" || "$AFTER_OWNER" == "bin" || "$AFTER_OWNER" == "sys" ]] \
       && [ "$AFTER_PERM" -le 644 ]; then

        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        ACTION_LOG="조치 완료. /etc/services 소유자 및 권한이 기준에 맞게 설정됨."
        EVIDENCE="소유자: $AFTER_OWNER, 권한: $AFTER_PERM (양호)"
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        ACTION_LOG="조치 수행 후에도 설정이 기준에 부합하지 않음. 수동 확인 필요."
        EVIDENCE="소유자: $AFTER_OWNER, 권한: $AFTER_PERM (취약)"
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="조치 대상 파일(/etc/services)이 존재하지 않습니다."
    EVIDENCE="파일 없음"
fi

# 2. JSON 표준 출력 (U-01 구조 그대로)
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "KISA 가이드라인에 따른 파일 권한 보안 설정이 완료되었습니다.",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF