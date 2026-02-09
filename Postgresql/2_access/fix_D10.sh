# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

# 1. 항목 정보 정의
ID="D-10"
CATEGORY="접근관리"
TITLE="원격 접속 IP 제한"
IMPORTANCE="상"

PGDATA="/var/lib/pgsql/data"
CONF_FILE="$PGDATA/postgresql.conf"
HBA_FILE="$PGDATA/pg_hba.conf"

ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# 2. 사전 체크
if [ ! -f "$CONF_FILE" ] || [ ! -f "$HBA_FILE" ]; then
    ACTION_RESULT="FAIL"
    ACTION_LOG="postgresql.conf 또는 pg_hba.conf 파일이 존재하지 않음"
else
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # [Step 1] 조치 전 상태 확인
    BEFORE_LISTEN=$(grep -E "^[^#]*listen_addresses" "$CONF_FILE" | awk -F= '{print $2}' | tr -d " '")
    BEFORE_HBA=$(grep -Ev "^\s*#" "$HBA_FILE" | grep -E "0\.0\.0\.0/0|::/0" | wc -l)

    BEFORE_SETTING="listen_addresses=${BEFORE_LISTEN:-default}, 전체IP허용규칙=${BEFORE_HBA}건"

    # [Step 2] 설정 파일 백업
    cp "$CONF_FILE" "${CONF_FILE}.bak_$TIMESTAMP"
    cp "$HBA_FILE"  "${HBA_FILE}.bak_$TIMESTAMP"
    ACTION_LOG="$ACTION_LOG 설정 파일 백업 완료;"

    # [Step 3] postgresql.conf listen_addresses 제한
    # * 또는 0.0.0.0 → localhost로 변경
    if grep -Eq "^[^#]*listen_addresses\s*=\s*'\*'|0\.0\.0\.0" "$CONF_FILE"; then
        sed -i "s/^[^#]*listen_addresses.*/listen_addresses = 'localhost'/" "$CONF_FILE"
        ACTION_LOG="$ACTION_LOG listen_addresses를 localhost로 제한;"
    fi

    # [Step 4] pg_hba.conf 전체 IP 허용 규칙 제거
    sed -i "/^[^#].*0\.0\.0\.0\/0/d" "$HBA_FILE"
    sed -i "/^[^#].*::\/0/d" "$HBA_FILE"
    ACTION_LOG="$ACTION_LOG 전체 IP 허용 규칙 제거;"

    # [Step 5] 설정 반영
    exportfs -ra 2>/dev/null
    systemctl reload postgresql 2>/dev/null || systemctl restart postgresql 2>/dev/null
    ACTION_LOG="$ACTION_LOG PostgreSQL 설정 재적용;"

    # [Step 6] 조치 후 상태 확인
    AFTER_LISTEN=$(grep -E "^[^#]*listen_addresses" "$CONF_FILE" | awk -F= '{print $2}' | tr -d " '")
    AFTER_HBA=$(grep -Ev "^\s*#" "$HBA_FILE" | grep -E "0\.0\.0\.0/0|::/0" | wc -l)

    AFTER_SETTING="listen_addresses=${AFTER_LISTEN:-default}, 전체IP허용규칙=${AFTER_HBA}건"
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat <<EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
