#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 홈 디렉토리가 존재하지 않는 계정이 발견되지 않도록 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#######################
# 삭제는 수동으로 처리
#######################

# 1. 변수 정의
ID="U-32"
TARGET_FILE="/etc/passwd"
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

ACTION_RESULT="PASS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

MISSING_HOME_USERS=()


# 2. 조치 로직
while IFS=: read -r username _ uid _ _ homedir shell; do
    if [ "$uid" -ge 1000 ]; then
        if [ ! -d "$homedir" ]; then
            MISSING_HOME_USERS+=("$username:$homedir")
            BEFORE_SETTING+="$username:$homedir (미존재); "

            # 홈 디렉토리 생성
            mkdir -p "$homedir"
            chown "$username:$username" "$homedir"
            chmod 700 "$homedir"

            AFTER_SETTING+="$username:$homedir (생성 완료); "
            ACTION_LOG+="계정 [$username] 홈 디렉토리 [$homedir] 생성 완료. "
        fi
    fi
done < "$TARGET_FILE"

if [ "${#MISSING_HOME_USERS[@]}" -eq 0 ]; then
    ACTION_LOG="조치 대상 계정 없음."
    BEFORE_SETTING="모든 사용자 홈 디렉토리 정상"
    AFTER_SETTING="변경 사항 없음"
else
    ACTION_RESULT="SUCCESS"
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF