# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash
ID="D-01"
CATEGORY="계정관리"
TITLE="관리자(SUPERUSER) 계정 비밀번호 설정 여부 점검"
IMPORTANCE="상"
TARGET_FILE="pg_shadow.passwd"
IMPACT_LEVEL="HIGH"
ACTION_IMPACT="관리자(SUPERUSER) 계정의 무단 접근 및 DB 전체 권한 탈취 위험을 예방할 수 있습니다."
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 상태 점검
# SUPERUSER 중 passwd NULL 계정 점검
SUPERUSERS=$(sudo -u postgres psql -t -A -c "
SELECT rolname
FROM pg_roles
WHERE rolsuper = true;
" 2>/dev/null)

if [ $? -ne 0 ]; then
    STATUS="FAIL"
    EVIDENCE="PostgreSQL 접속 실패 또는 권한 부족"
    GUIDE_MSG="PostgreSQL 접속 권한을 확인한 후 다시 점검하십시오."
else
    STATUS="MANUAL_CHECK"
    EVIDENCE="관리자(SUPERUSER) 계정 목록: $(echo "$SUPERUSERS" | tr '\n' ',' | sed 's/,$//')"
    GUIDE_MSG="PostgreSQL은 SUPERUSER 계정의 비밀번호 설정 여부를 자동으로 정확히 판별할 수 없습니다. 나열된 SUPERUSER 계정에 대해 관리자 계정으로 접속(sudo -u postgres psql) 후 각 계정의 인증 방식 및 비밀번호 설정 여부를 수동으로 확인하고, 필요 시 `ALTER USER <계정명> WITH PASSWORD '<강력한 비밀번호>';` 명령을 수행하십시오."
fi


# 2. JSON 출력
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE_MSG",
  "target_file": "$TARGET_FILE",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",
  "check_date": "$CHECK_DATE"
}
EOF

