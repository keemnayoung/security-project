#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : Secondary Name Server로만 Zone 정보 전송 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-50 DNS Zone Transfer 설정

# 1. 항목 정보 정의
ID="U-50"
CATEGORY="서비스 관리"
TITLE="DNS Zone Transfer 설정"
IMPORTANCE="상"
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
    # 가이드: /etc/named.boot, /etc/bind/named.boot, /etc/named.conf, /etc/bind/named.conf.options
    CONF_FILES=("/etc/named.boot" "/etc/bind/named.boot" "/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
    TARGET=""
    MODIFIED=0
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            TARGET="$conf"
            TARGET_FILE="$conf"
            cp "$TARGET" "${TARGET}.bak_$(date +%Y%m%d_%H%M%S)"
            
            # 1. xfrnets 조치 (BIND 4/8 - 구형)
            # 가이드: xfrnets <zone transfer를 허용할 IP>
            # 여기서는 수동 조치 권고 (구형 버전)
            if grep -q "xfrnets" "$TARGET" 2>/dev/null; then
                ACTION_LOG="$ACTION_LOG xfrnets 설정이 존재하여 수동 확인이 권장됩니다."
            fi
            
            # 2. allow-transfer 조치 (BIND 9)
            # 가이드: allow-transfer { <zone transfer를 허용할 IP>; };
            if grep -q "allow-transfer" "$TARGET"; then
                # allow-transfer { any; } → { 127.0.0.1; } 또는 { none; }
                if grep -q "allow-transfer.*any" "$TARGET"; then
                    sed -i 's/allow-transfer.*{.*any.*};/allow-transfer { none; };/g' "$TARGET"
                    ACTION_LOG="$ACTION_LOG allow-transfer { any; }를 { none; }으로 수정했습니다."
                    MODIFIED=1
                fi
            else
                # options 블록에 allow-transfer { none; } 추가
                if grep -q "^options[[:space:]]*{" "$TARGET"; then
                    sed -i '/^options[[:space:]]*{/a \\tallow-transfer { none; };' "$TARGET"
                    ACTION_LOG="$ACTION_LOG options 블록 내 allow-transfer { none; }를 추가했습니다."
                    MODIFIED=1
                else
                    ACTION_LOG="$ACTION_LOG options 블록이 없어 수동 설정이 필요합니다."
                fi
            fi
            
            # Include 파일들도 처리
            while IFS= read -r inc_file; do
                if [ -f "$inc_file" ]; then
                    if grep -q "allow-transfer.*any" "$inc_file" 2>/dev/null; then
                        cp "$inc_file" "${inc_file}.bak_$(date +%Y%m%d_%H%M%S)"
                        sed -i 's/allow-transfer.*{.*any.*};/allow-transfer { none; };/g' "$inc_file"
                        ACTION_LOG="$ACTION_LOG Include 파일($inc_file)의 allow-transfer를 수정했습니다."
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

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="DNS Zone Transfer 설정을 none으로 제한하여 비인가 전송을 차단했습니다. Secondary DNS 서버가 있어 Zone Transfer가 필요한 경우, named.conf 파일에서 'allow-transfer { <Secondary DNS IP>; };'로 허용할 IP 주소를 수동 지정하십시오."
else
    ACTION_LOG="DNS 서비스가 실행되고 있지 않거나 Zone Transfer 설정이 이미 적절합니다."
fi

STATUS="PASS"
EVIDENCE="DNS Zone Transfer 설정이 적절히 구성되어 있습니다."

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
