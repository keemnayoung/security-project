#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Criteria_Good : SNMP Community String 기본값인 public/private가 아니며, 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상
# @Criteria_Bad : public/private 사용 또는 복잡성 기준 미달
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-60 SNMP Community String 복잡성 설정

# 1. 항목 정보 정의
ID="U-60"
CATEGORY="서비스 관리"
TITLE="SNMP Community String 복잡성 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
CHECKED_COUNT=0

is_strong_community() {
    local value="$1"
    local lower
    local len

    [ -z "$value" ] && return 1

    lower=$(echo "$value" | tr '[:upper:]' '[:lower:]')
    if [ "$lower" = "public" ] || [ "$lower" = "private" ]; then
        return 1
    fi

    len=${#value}

    # 영문+숫자만 구성된 경우 10자 이상
    if echo "$value" | grep -qE '^[A-Za-z0-9]+$'; then
        if echo "$value" | grep -qE '[A-Za-z]' && echo "$value" | grep -qE '[0-9]' && [ "$len" -ge 10 ]; then
            return 0
        fi
        return 1
    fi

    # 영문+숫자+특수문자 포함된 경우 8자 이상
    if echo "$value" | grep -qE '[A-Za-z]' && \
       echo "$value" | grep -qE '[0-9]' && \
       echo "$value" | grep -qE '[^A-Za-z0-9]' && \
       [ "$len" -ge 8 ]; then
        return 0
    fi

    return 1
}

assess_community() {
    local source="$1"
    local value="$2"

    [ -z "$value" ] && return

    CHECKED_COUNT=$((CHECKED_COUNT + 1))

    if is_strong_community "$value"; then
        EVIDENCE="$EVIDENCE $source community string이 복잡성 기준을 충족합니다."
    else
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $source community string이 복잡성 기준을 충족하지 않습니다($value)."
    fi
}

# SNMP 서비스 활성화 여부 확인
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    STATUS="PASS"
    EVIDENCE="SNMP 서비스가 비활성화되어 있습니다."
else
    CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
        TARGET_FILE="$CONF"
        FILE_HASH=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}')

        V3_USERS=$(grep -Ev '^[[:space:]]*#' "$CONF" | grep -E '^(createUser|rouser|rwuser)[[:space:]]')
        if [ -n "$V3_USERS" ]; then
            EVIDENCE="$EVIDENCE SNMPv3 사용자 설정이 확인되었습니다."
        fi

        # RedHat 계열: com2sec notConfigUser <source> <community>
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            community=$(echo "$line" | awk '{print $4}')
            [ -z "$community" ] && community=$(echo "$line" | awk '{print $NF}')
            assess_community "com2sec" "$community"
        done < <(grep -Ev '^[[:space:]]*#' "$CONF" | grep -E '^[[:space:]]*com2sec[[:space:]]')

        # Debian 계열: rocommunity/rwcommunity <community> [source]
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            community=$(echo "$line" | awk '{print $2}')
            assess_community "ro/rwcommunity" "$community"
        done < <(grep -Ev '^[[:space:]]*#' "$CONF" | grep -E '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]')

        if [ "$CHECKED_COUNT" -eq 0 ]; then
            if [ -n "$V3_USERS" ]; then
                STATUS="PASS"
                EVIDENCE="SNMPv3 기반 인증을 사용하며, Community String 기반 설정이 없습니다."
            else
                VULNERABLE=1
                EVIDENCE="SNMP Community String 또는 SNMPv3 사용자 설정을 찾을 수 없습니다."
            fi
        fi
    else
        STATUS="PASS"
        EVIDENCE="$CONF 파일이 존재하지 않습니다."
    fi

    if [ "$VULNERABLE" -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP Community String 복잡성이 미흡하여 추측 공격에 노출될 수 있습니다.$EVIDENCE"
    elif [ "$STATUS" != "PASS" ]; then
        :
    else
        STATUS="PASS"
    fi
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존 Community String 기반 연동 장비의 인증 정보도 함께 변경해야 하므로 적용 전에 연동 대상 설정 변경 계획을 수립해야 합니다."

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "SNMP Community String은 public/private를 사용하지 말고, 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상으로 설정한 뒤 서비스를 재시작해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
