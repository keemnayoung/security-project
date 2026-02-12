#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-27"
CATEGORY="파일 및 디렉토리 관리"
TITLE="\$HOME/.rhosts, hosts.equiv 사용 금지"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"


TARGET_FILES=("/etc/hosts.equiv" "\$HOME/.rhosts")
RHOSTS_FILES=$(find /home -name ".rhosts" 2>/dev/null)

if [ ${#TARGET_FILES[@]} -eq 0 ] && [ -z "$RHOSTS_FILES" ]; then
    ACTION_RESULT="ERROR"
    ACTION_LOG="조치 대상 파일이 존재하지 않습니다."
    EVIDENCE="조치 대상 파일이 존재하지 않습니다."
    GUIDE="/etc/hosts.equiv, \$HOME/.rhosts 파일 소유자를 root 또는 해당 계정으로 변경해주시고 권한도 600 이하로 변경해주세요. 각 파일에 허용 호스트 및 계정을 등록해주세요."
else
    for file in "${TARGET_FILES[@]}" $RHOSTS_FILES; do
        if [ -f "$file" ]; then
            OWNER=$(stat -c %U "$file")
            PERM=$(stat -c %a "$file")
            PLUS_EXIST=$(grep -E '^\s*\+' "$file" 2>/dev/null)

            BEFORE="owner=$OWNER,perm=$PERM,plus=$( [ -n "$PLUS_EXIST" ] && echo yes || echo no )"
            
            # 소유자 조치
            if [[ "$file" == "/etc/hosts.equiv" ]]; then
                chown root "$file"
            else
                FILE_USER=$(basename "$(dirname "$file")")
                chown "$FILE_USER" "$file"
            fi

            # 권한 조치
            chmod 600 "$file"

            # "+" 제거
            sed -i '/^\s*\+/d' "$file"

            # 조치 후 확인
            OWNER_AFTER=$(stat -c %U "$file")
            PERM_AFTER=$(stat -c %a "$file")
            PLUS_AFTER=$(grep -E '^\s*\+' "$file" 2>/dev/null)
            AFTER="owner=$OWNER_AFTER,perm=$PERM_AFTER,plus=$( [ -n "$PLUS_AFTER" ] && echo yes || echo no )"

            EVIDENCE+="$file (조치 전 상태: $BEFORE, 조치 후 상태: $AFTER), "
            ACTION_LOG+="$file 조치가 완료되었습니다. "
        fi
    done

    # 마지막 쉼표 제거
    EVIDENCE=${EVIDENCE%,}
    ACTION_LOG=${ACTION_LOG%,}

    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF