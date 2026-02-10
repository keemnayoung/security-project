# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-25"
CATEGORY="패치관리"
TITLE="DBMS 보안 패치 적용"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="server_version"
ACTION_IMPACT="DBMS 버전 업데이트 시 기존 시스템 구성 요소 및 응용 프로그램과의 호환성 문제가 발생할 수 있으므로 사전 검증이 필요합니다."
IMPACT_LEVEL="HIGH"

version=$(psql -U postgres -t -c "SHOW server_version;" | xargs)
major_ver=$(echo "$version" | cut -d'.' -f1)
if [ "$major_ver" -ge 14 ]; then
  STATUS="양호"
  EVIDENCE="보안 패치 지원 버전(PostgreSQL $version) 사용 중"
else
  STATUS="취약"
  EVIDENCE="보안 패치 지원 종료(EOL) 또는 취약 가능 버전(PostgreSQL $version) 사용 중"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL은 정기적으로 보안 패치를 제공하므로, 보안 패치가 적용된 최신 안정 버전을 사용해야 합니다. 버전 업그레이드 전 테스트 환경에서 충분한 검증이 필요합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
