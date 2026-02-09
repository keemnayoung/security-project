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

#기준세우기 애매해서 postgresql 문서 참고해서 가이드안내 정도로만 구성을 했습니다.

#!/bin/bash
# [조치 안내] D-03 비밀번호 사용기간 및 복잡도 정책 설정 가이드 (인증 방식 기반)

ID="D-03"
CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')
PG_HBA="/var/lib/pgsql/data/pg_hba.conf"

# pg_hba.conf 인증 방식 확인
AUTH_METHODS=$(grep -Ev '^\s*#|^\s*$' "$PG_HBA" 2>/dev/null | awk '{print $NF}' | sort -u)

# 인증 방식별 판단 및 가이드 요약
if echo "$AUTH_METHODS" | grep -Eq 'password|md5|scram-sha-256'; then
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 조치 필요: PostgreSQL이 DB 내부 인증(password/md5/scram-sha-256)을 사용 중입니다. PostgreSQL은 비밀번호 사용기간·복잡도 정책을 기본 제공하지 않으므로 PAM 인증 전환, AD/LDAP 연계, 또는 비밀번호 정책 확장 모듈 사용 여부를 검토해야 합니다."

elif echo "$AUTH_METHODS" | grep -Eq '^pam$'; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: PostgreSQL이 PAM 인증을 사용 중입니다. OS 비밀번호 정책(/etc/security/pwquality.conf, /etc/login.defs)이 기관 정책에 맞게 설정되어 있는지 추가 확인이 필요합니다."

elif echo "$AUTH_METHODS" | grep -Eq 'ldap|gss|sspi'; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: PostgreSQL이 중앙 인증(LDAP/AD)과 연계되어 있습니다. 비밀번호 사용기간 및 복잡도 정책은 중앙 인증 시스템에서 관리됩니다."

else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 확인 필요: pg_hba.conf에서 인증 방식이 혼합되었거나 명확히 식별되지 않습니다. 인증 방식별 비밀번호 정책 적용 위치(DB/OS/중앙 인증)를 구분하여 운영 정책을 확인하십시오."
fi

# JSON 출력 (D-01 형식 고정)
cat <<EOF
{
  "check_id": "$ID",
  "status": "$CURRENT_STATUS",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF


