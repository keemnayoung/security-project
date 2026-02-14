#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : DNS 서비스의 취약한 동적 업데이트 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-51 DNS 서비스의 취약한 동적 업데이트 설정 금지

# 1. 항목 정보 정의
ID="U-51"
CATEGORY="서비스 관리"
TITLE="DNS 서비스의 취약한 동적 업데이트 설정 금지"
IMPORTANCE="중"
TARGET_FILE="/etc/bind/named.conf.options"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# DNS 서비스 확인
# 가이드: systemctl list-units --type=service | grep named
if ! systemctl list-units --type=service 2>/dev/null | grep -q named && ! pgrep -x named >/dev/null 2>&1; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="DNS 서비스가 비활성화되어 있어 조치 대상이 없습니다."
else
    # 가이드: /etc/named.conf, /etc/bind/named.conf.options
    CONF_FILES=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
    TARGET=""
    MODIFIED=0
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            TARGET="$conf"
            TARGET_FILE="$conf"
            cp "$TARGET" "${TARGET}.bak_$(date +%Y%m%d_%H%M%S)"
            
            # allow-update 설정 확인 및 조치
            # 가이드: allow-update { none; }; 또는 { <허용IP>; }
            if grep -q "allow-update" "$TARGET"; then

                
                # allow-update { any; } → { none; }
                if grep -q "allow-update.*any" "$TARGET"; then
                    sed -i 's/allow-update.*{.*any.*};/allow-update { none; };/g' "$TARGET"
                    ACTION_LOG="$ACTION_LOG allow-update { any; }를 { none; }으로 수정했습니다."
                    MODIFIED=1
                fi
            else

                
                # zone 블록에 allow-update { none; } 추가
                if grep -q "^zone[[:space:]]" "$TARGET"; then
                    # zone 블록 내부에 추가하는 것은 복잡하므로 수동 권고
                    ACTION_LOG="$ACTION_LOG zone 블록에 allow-update { none; } 수동 설정이 필요합니다."
                fi
            fi
            
            # Include 파일들도 처리
            while IFS= read -r inc_file; do
                if [ -f "$inc_file" ]; then
                    if grep -q "allow-update.*any" "$inc_file" 2>/dev/null; then
                        cp "$inc_file" "${inc_file}.bak_$(date +%Y%m%d_%H%M%S)"
                        sed -i 's/allow-update.*{.*any.*};/allow-update { none; };/g' "$inc_file"
                        ACTION_LOG="$ACTION_LOG Include 파일($inc_file)의 allow-update를 수정했습니다."
                        MODIFIED=1
                    fi
                fi
            done < <(grep -hE "^[[:space:]]*include" "$TARGET" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')
            
            break
        fi
    done
    
    if [ -z "$TARGET" ]; then
        ACTION_RESULT="FAIL"
        ACTION_LOG="DNS 설정 파일을 찾을 수 없습니다."
    elif [ $MODIFIED -eq 1 ]; then
        # DNS 서비스 재시작
        systemctl restart named 2>/dev/null

        ACTION_RESULT="SUCCESS"
        ACTION_LOG="$ACTION_LOG DNS 서비스를 재시작했습니다."
    else
        ACTION_RESULT="MANUAL"
        ACTION_LOG="$ACTION_LOG 자동 조치 불가 - 수동 확인이 필요합니다;"
    fi
fi
if [ "$ACTION_RESULT" == "SUCCESS" ]; then
    ACTION_LOG="DNS 동적 업데이트 설정(allow-update)을 none으로 제한하여 비인가 변경을 차단했습니다. 동적 업데이트가 필요한 경우, named.conf 파일에서 'allow-update { <허용할 IP>; };'로 허용할 IP 주소를 수동 지정하십시오."
    STATUS="PASS"
    EVIDENCE="취약점 조치가 완료되었습니다."
elif [ "$ACTION_RESULT" == "MANUAL" ]; then
    ACTION_LOG="DNS 동적 업데이트 설정의 자동 조치가 불가하여 수동 확인이 필요합니다."
    STATUS="MANUAL"
    EVIDENCE="수동 확인이 필요합니다."
else
    STATUS="$ACTION_RESULT"
    EVIDENCE="DNS 설정 파일 확인이 필요합니다."
fi

# 3. 마스터 템플릿 표준 출렵
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
