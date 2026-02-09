#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 변수 정의
ID="U-67"
TARGET_FILE="/var/log"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

VULN_FOUND=0


# 2. 조치 로직
if [ -d "$TARGET_FILE" ]; then
    while IFS= read -r file; do
        OWNER=$(stat -c %U "$file" 2>/dev/null)
        PERM=$(stat -c %a "$file" 2>/dev/null)

        BEFORE_SETTING+="$file (owner=$OWNER, perm=$PERM)\n"

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
            VULN_FOUND=1

            chown root "$file" 2>/dev/null
            chmod 644 "$file" 2>/dev/null

            NEW_OWNER=$(stat -c %U "$file" 2>/dev/null)
            NEW_PERM=$(stat -c %a "$file" 2>/dev/null)

            ACTION_LOG+="조치 완료: $file (owner=$NEW_OWNER, perm=$NEW_PERM)\n"
        fi

        AFTER_SETTING+="$file (owner=$(stat -c %U "$file"), perm=$(stat -c %a "$file"))\n"

    done < <(find "$TARGET_FILE" -type f 2>/dev/null)

    if [ "$VULN_FOUND" -eq 0 ]; then
        ACTION_LOG="조치 대상 로그 파일 없음"
        BEFORE_SETTING="모든 로그 파일이 적절한 소유자 및 권한을 가짐"
        AFTER_SETTING="변경 사항 없음"
    fi
else
    ACTION_RESULT="FAIL"
    ACTION_LOG="/var/log 디렉터리가 존재하지 않음"
    BEFORE_SETTING="N/A"
    AFTER_SETTING="N/A"
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$(echo -e "$BEFORE_SETTING" | sed ':a;N;$!ba;s/\n/ | /g')",
  "after_setting": "$(echo -e "$AFTER_SETTING" | sed ':a;N;$!ba;s/\n/ | /g')",
  "action_log": "$(echo -e "$ACTION_LOG" | sed ':a;N;$!ba;s/\n/ | /g')",
  "action_date": "$ACTION_DATE"
}
EOF