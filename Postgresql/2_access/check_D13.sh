# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스 제거
# @Description : 사용하지 않는 불필요한 ODBC/OLE-DB가 설치되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-13"
CATEGORY="접근관리"
TITLE="ODBC/OLE-DB 데이터 소스 관리"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="Windows OS 전용 항목으로 ODBC/OLE-DB 데이터 소스가 존재하지 않아 PostgreSQL에는 적용되지 않습니다."
TARGET_FILE="Listener"
ACTION_IMPACT="PostgreSQL은 ODBC/OLE-DB 데이터 소스를 제공하지 않아 해당없습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL은 ODBC/OLE-DB 데이터 소스를 제공하지 않아 해당없습니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE" 
}
EOF
