# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : DBMS 계정 비밀번호에 대해 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-03"
CATEGORY="계정관리"
TITLE="비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정"
IMPORTANCE="상"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="인증 방식 기반 수동 점검 필요"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="비밀번호 정책 적용 위치(DB/OS/중앙인증)를 확인하여 기관 정책에 맞게 설정해야 합니다."

#########################################
# 1. 실제 pg_hba.conf 경로 조회
#########################################

HBA_FILE=$(sudo -u postgres psql -t -A -c "SHOW hba_file;" 2>/dev/null)

if [ -z "$HBA_FILE" ]; then
    STATUS="FAIL"
    EVIDENCE="pg_hba.conf 경로 확인 실패"
    GUIDE_MSG="PostgreSQL 접속 권한을 확인하십시오."
else

    #########################################
    # 2. 인증 방식 추출
    #########################################

    AUTH_METHODS=$(grep -Ev '^\s*#|^\s*$' "$HBA_FILE" 2>/dev/null | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')

    #########################################
    # 3. 인증 방식별 가이드 구성
    #########################################

    if echo "$AUTH_METHODS" | grep -Eq 'password|md5|scram-sha-256'; then
        GUIDE_MSG="현재 인증 방식: ${AUTH_METHODS}

DB 내부 인증 사용 중입니다.

확인 항목:
1) 암호 저장 방식 확인:
   SHOW password_encryption;

2) 계정 만료일 확인:
   SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolcanlogin=true;

PostgreSQL은 기본적으로 비밀번호 복잡도/사용기간 정책을 제공하지 않으므로,
기관 정책에 따른 별도 정책 적용 여부를 확인해야 합니다."
    
    elif echo "$AUTH_METHODS" | grep -Eq 'pam'; then
        GUIDE_MSG="현재 인증 방식: ${AUTH_METHODS}

PAM 인증 사용 중입니다.

확인 항목:
1) /etc/security/pwquality.conf (복잡도)
2) /etc/login.defs (PASS_MAX_DAYS 등 사용기간)
3) chage -l 계정명

OS 비밀번호 정책이 기관 정책에 부합하는지 확인하십시오."
    
    elif echo "$AUTH_METHODS" | grep -Eq 'ldap|gss|sspi'; then
        GUIDE_MSG="현재 인증 방식: ${AUTH_METHODS}

중앙 인증(LDAP/AD) 연계 사용 중입니다.

확인 항목:
1) AD Domain Password Policy
2) 중앙 인증 서버의 비밀번호 복잡도 정책
3) 계정 만료 정책

중앙 인증 시스템에서 정책 적용 여부를 확인해야 합니다."
    
    else
        GUIDE_MSG="현재 인증 방식: ${AUTH_METHODS}

인증 방식이 혼합되어 있거나 식별이 명확하지 않습니다.

각 인증 방식별로 정책 적용 위치(DB/OS/중앙 인증)를 구분하여
기관 정책에 맞게 수동 점검하십시오."
    fi

    EVIDENCE="실제 pg_hba.conf 경로: ${HBA_FILE}. 적용 인증 방식: ${AUTH_METHODS}"
fi

#########################################
# 4. JSON escape
#########################################

EVIDENCE_ESCAPED=$(echo "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
GUIDE_ESCAPED=$(echo "$GUIDE_MSG" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
ACTION_LOG_ESCAPED=$(echo "$ACTION_LOG" | sed 's/"/\\"/g')

#########################################
# 5. JSON 출력
#########################################

cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE_ESCAPED",
  "guide": "$GUIDE_ESCAPED",
  "target_file": "$HBA_FILE",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG_ESCAPED",
  "check_date": "$DATE"
}
EOF




