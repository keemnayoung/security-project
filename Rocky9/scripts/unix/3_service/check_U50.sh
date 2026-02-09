#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : DNS Zone Transfer가 제한되어 있는지 점검
# @Criteria_Good : DNS Zone Transfer가 허용된 IP에 대해서만 제한된 경우
# @Criteria_Bad : DNS Zone Transfer가 모든 호스트에게 허용된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-50 DNS Zone Transfer 설정

# 1. 항목 정보 정의
ID="U-50"
CATEGORY="서비스관리"
TITLE="DNS Zone Transfer 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/bind/named.conf.options"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# DNS 서비스(named) 실행 여부 확인
# 가이드: systemctl list-units --type=service | grep named
if ! systemctl list-units --type=service 2>/dev/null | grep -q named && ! pgrep -x named >/dev/null 2>&1; then
    STATUS="PASS"
    EVIDENCE="DNS 서비스 미사용 (양호)"
else
    # 설정 파일 찾기 (데비안/우분투: named.conf.options, RHEL: named.conf)
    # 가이드: /etc/named.boot, /etc/bind/named.boot, /etc/named.conf, /etc/bind/named.conf.options
    CONF_FILES=("/etc/named.boot" "/etc/bind/named.boot" "/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
    FOUND_CONF=0
    
    # Include 파일 목록을 담을 배열
    INCLUDE_FILES=()
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            FOUND_CONF=1
            TARGET_FILE="$conf"
            FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
            
            # Include 구문으로 참조하는 파일 찾기
            # 가이드: DNS 설정 파일의 Include 구문으로 참조하는 파일명 점검
            while IFS= read -r inc_file; do
                if [ -f "$inc_file" ]; then
                    INCLUDE_FILES+=("$inc_file")
                fi
            done < <(grep -hE "^[[:space:]]*include" "$conf" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')
            
            # 1. xfrnets 확인 (BIND 4/8 - 구형)
            # 가이드: cat /etc/named.boot | grep xfrnets
            if grep -q "xfrnets" "$conf"; then
                SETTING=$(grep "xfrnets" "$conf")
                EVIDENCE="$EVIDENCE $conf: $SETTING;"
            fi
            
            # 2. allow-transfer 확인 (BIND 9)
            # 가이드: cat /etc/named.conf | grep allow-transfer
            if grep -q "allow-transfer" "$conf"; then
                SETTING=$(grep "allow-transfer" "$conf" | sed 's/^[ \t]*//')
                if echo "$SETTING" | grep -q "any"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $conf: allow-transfer { any; } 설정 발견;"
                else
                    EVIDENCE="$EVIDENCE $conf: $SETTING (제한 설정됨);"
                fi
            else
                # allow-transfer 설정이 없으면 기본적으로 allow (BIND 9 기준)
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $conf: allow-transfer 설정 없음 (기본값: 모든 호스트 허용);"
            fi
        fi
    done
    
    # Include 파일들도 점검
    for inc_file in "${INCLUDE_FILES[@]}"; do
        EVIDENCE="$EVIDENCE Include 파일: $inc_file;"
        
        # xfrnets 확인
        if grep -q "xfrnets" "$inc_file" 2>/dev/null; then
            SETTING=$(grep "xfrnets" "$inc_file")
            EVIDENCE="$EVIDENCE $inc_file: $SETTING;"
        fi
        
        # allow-transfer 확인
        if grep -q "allow-transfer" "$inc_file" 2>/dev/null; then
            SETTING=$(grep "allow-transfer" "$inc_file" | sed 's/^[ \t]*//')
            if echo "$SETTING" | grep -q "any"; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $inc_file: allow-transfer { any; } 발견;"
            else
                EVIDENCE="$EVIDENCE $inc_file: $SETTING;"
            fi
        fi
    done
    
    if [ $FOUND_CONF -eq 0 ]; then
        STATUS="PASS"
        EVIDENCE="DNS 설정 파일을 찾을 수 없음"
    elif [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="DNS Zone Transfer 제한 미흡: $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="DNS Zone Transfer가 제한되어 있음: $EVIDENCE"
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
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "named.conf에서 allow-transfer { none; }; 또는 신뢰된 Secondary DNS IP만 허용하도록 설정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
