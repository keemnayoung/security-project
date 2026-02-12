# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @IMPORTANCE    : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-26"
CATEGORY="패치관리"
TITLE="DB 감사 로그 정책"
DESCRIPTION="감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="logging_collector"
ACTION_IMPACT="DB 감사 로그 수집이 활성화됩니다. 다만 로그 증가로 인해 디스크 사용량이 증가할 수 있으므로 주기적인 로그 관리가 필요합니다."
IMPACT_LEVEL="HIGH"

log_collector=$(psql -U postgres -t -c "SHOW logging_collector;" 2>/dev/null | xargs)

if [ "$log_collector" = "on" ]; then
  STATUS="PASS"
  EVIDENCE="DB 감사 로그 수집 기능(logging_collector)이 활성화됨"
else
  STATUS="FAIL"
  EVIDENCE="DB 감사 로그 수집 기능(logging_collector)이 비활성화됨"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL 데이터 디렉터리의 postgresql.conf 파일에서 logging_collector를 on으로 설정하십시오. 설정 변경 후 systemctl restart postgresql 명령을 통해 서비스를 재시작하여 적용 여부를 확인해야 합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
