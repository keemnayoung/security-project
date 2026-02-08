#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux 9
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String이 추측하기 어렵게 설정되어 있는지 점검
# @Criteria_Good : Community String이 public/private이 아닌 복잡한 값으로 설정된 경우
# @Criteria_Bad : Community String이 public/private 등 기본값으로 설정된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-60 SNMP Community String 복잡성 설정

# 1. 항목 정보 정의
ID="U-60"
CATEGORY="서비스관리"
TITLE="SNMP Community String 복잡성 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# SNMP 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    STATUS="PASS"
    EVIDENCE="SNMP 서비스가 비활성화되어 있음"
else
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        FILE_HASH=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}')
        
        # [Redhat 계열] com2sec 설정 확인
        # 가이드: com2sec notConfigUser default <Community String>
        COM2SEC=$(grep -v "^#" "$CONF" | grep "com2sec")
        
        if [ -n "$COM2SEC" ]; then
            # public/private 사용 여부 확인
            if echo "$COM2SEC" | grep -qE "\s(public|private)\s*$"; then
                VULNERABLE=1
                EVIDENCE="com2sec 설정에 취약한 Community String(public/private) 사용: $COM2SEC"
            else
                EVIDENCE="com2sec 설정 존재 (기본값 아님)"
            fi
        fi
        
        # rocommunity/rwcommunity 확인 (호환성)
        ROCOMMUNITY=$(grep -v "^#" "$CONF" | grep -E "^rocommunity|^rwcommunity")
        
        if [ -n "$ROCOMMUNITY" ]; then
            if echo "$ROCOMMUNITY" | grep -qE "public|private"; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE rocommunity/rwcommunity에 취약한 Community String(public/private) 사용"
            fi
        fi
        
        # 설정이 아예 없는 경우
        if [ -z "$COM2SEC" ] && [ -z "$ROCOMMUNITY" ]; then
            EVIDENCE="Community String 설정을 찾을 수 없음 (확인 필요)"
        fi
    else
        STATUS="PASS"
        EVIDENCE="$CONF 파일이 존재하지 않음"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP Community String 복잡성 미흡: $EVIDENCE"
    fi
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

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
    "guide": "snmpd.conf에서 public/private 대신 추측 불가능한 community string으로 변경 후 서비스 재시작하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
