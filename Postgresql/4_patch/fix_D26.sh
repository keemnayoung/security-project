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
CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

PGDATA="/var/lib/pgsql/data"
CONF_FILE="$PGDATA/postgresql.conf"

# 1. 현재 logging_collector 상태 확인
CURRENT_VAL=$(sudo -u postgres psql -t -c "SHOW logging_collector;" 2>/dev/null | xargs)

if [ "$CURRENT_VAL" = "on" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: DB 감사 로그 수집 기능(logging_collector)이 이미 활성화되어 있음"
else
    # 2. 설정 파일 존재 여부 확인
    if [ ! -f "$CONF_FILE" ]; then
        CURRENT_STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="오류: postgresql.conf 파일을 찾을 수 없어 자동 조치를 수행할 수 없음"
    else
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)

        # 3. postgresql.conf 백업
        cp "$CONF_FILE" "${CONF_FILE}.bak_$TIMESTAMP" 2>/dev/null

        # 4. logging_collector 설정 변경
        if grep -Eq "^[^#]*logging_collector" "$CONF_FILE"; then
            sed -i "s/^[^#]*logging_collector.*/logging_collector = on/" "$CONF_FILE"
        else
            echo "logging_collector = on" >> "$CONF_FILE"
        fi

        # 5. 설정 반영 (재시작 필요)
        systemctl restart postgresql 2>/dev/null

        # 6. 결과 재확인
        NEW_VAL=$(sudo -u postgres psql -t -c "SHOW logging_collector;" 2>/dev/null | xargs)

        if [ "$NEW_VAL" = "on" ]; then
            CURRENT_STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="자동 조치 완료: postgresql.conf에 logging_collector=on 설정 후 PostgreSQL 재시작하여 감사 로그 수집 기능을 활성화함"
        else
            CURRENT_STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="자동 조치 실패: logging_collector 설정 변경 후에도 기능이 활성화되지 않음"
        fi
    fi
fi

# 7. JSON 출력 
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE_MSG",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE",
  "check_date": "$ACTION_DATE"
}
EOF

