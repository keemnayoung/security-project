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
# @Platform : LINUX
# @Importance : 상
# @Title : DNS Dynamic Update 설정
# @Description : DNS Dynamic Update 기능을 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-51 DNS Dynamic Update 설정

# 1. 항목 정보 정의
ID="U-51"
CATEGORY="서비스관리"
TITLE="DNS Dynamic Update 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/bind/named.conf.options"

# 2. 보완 로직
ACTION_RESULT="MANUAL"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# DNS 서비스 확인
# 가이드: systemctl list-units --type=service | grep named
if ! systemctl list-units --type=service 2>/dev/null | grep -q named && ! pgrep -x named >/dev/null 2>&1; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="DNS 서비스 미사용 (양호)"
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
                BEFORE_SETTING="$BEFORE_SETTING $(grep 'allow-update' "$TARGET");"
                
                # allow-update { any; } → { none; }
                if grep -q "allow-update.*any" "$TARGET"; then
                    sed -i 's/allow-update.*{.*any.*};/allow-update { none; };/g' "$TARGET"
                    ACTION_LOG="$ACTION_LOG allow-update { any; } -> { none; } 수정;"
                    MODIFIED=1
                fi
            else
                BEFORE_SETTING="$BEFORE_SETTING allow-update 설정 없음;"
                
                # zone 블록에 allow-update { none; } 추가
                if grep -q "^zone[[:space:]]" "$TARGET"; then
                    # zone 블록 내부에 추가하는 것은 복잡하므로 수동 권고
                    ACTION_LOG="$ACTION_LOG zone 블록에 allow-update { none; } 수동 설정 필요;"
                fi
            fi
            
            # Include 파일들도 처리
            while IFS= read -r inc_file; do
                if [ -f "$inc_file" ]; then
                    if grep -q "allow-update.*any" "$inc_file" 2>/dev/null; then
                        cp "$inc_file" "${inc_file}.bak_$(date +%Y%m%d_%H%M%S)"
                        sed -i 's/allow-update.*{.*any.*};/allow-update { none; };/g' "$inc_file"
                        ACTION_LOG="$ACTION_LOG Include 파일($inc_file) allow-update 수정;"
                        MODIFIED=1
                    fi
                fi
            done < <(grep -hE "^[[:space:]]*include" "$TARGET" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')
            
            break
        fi
    done
    
    if [ -z "$TARGET" ]; then
        ACTION_RESULT="FAIL"
        ACTION_LOG="DNS 설정 파일을 찾을 수 없음"
    elif [ $MODIFIED -eq 1 ]; then
        # DNS 서비스 재시작
        systemctl restart named 2>/dev/null
        AFTER_SETTING=$(grep "allow-update" "$TARGET" 2>/dev/null)
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="$ACTION_LOG DNS 서비스 재시작;"
    else
        ACTION_RESULT="MANUAL"
        ACTION_LOG="$ACTION_LOG 자동 조치 불가 - 수동 확인 필요;"
    fi
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
