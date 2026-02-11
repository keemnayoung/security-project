#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 안전한 버전의 데이터베이스를 사용하고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-25"
CATEGORY="DBMS"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"
TARGET_FILE="mysql_binary"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT=5
CMD_TIMEOUT=8
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"

run_cmd() {
    local cmd="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${CMD_TIMEOUT}s bash -lc "$cmd" 2>/dev/null
    else
        bash -lc "$cmd" 2>/dev/null
    fi
    return $?
}

extract_semver() {
    # 문자열에서 첫 번째 x.y.z 형태 추출
    echo "$1" | sed -nE 's/.*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1
}

version_ge() {
    # $1 >= $2 이면 0
    local current="$1"
    local candidate="$2"
    [[ -z "$current" || -z "$candidate" ]] && return 1
    local top
    top=$(printf '%s\n%s\n' "$current" "$candidate" | sort -V | tail -n 1)
    [[ "$top" == "$current" ]]
}

# 1) 현재 MySQL 버전 조회
if [[ -n "$TIMEOUT_BIN" ]]; then
    VERSION_RAW=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "SELECT VERSION();" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    VERSION_RAW=$($MYSQL_CMD "SELECT VERSION();" 2>/dev/null || echo "ERROR")
fi

if [[ "$VERSION_RAW" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="DB 버전 정보 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-25 점검에 실패했습니다."
elif [[ "$VERSION_RAW" == "ERROR" || -z "$VERSION_RAW" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 현재 제품 버전을 확인할 수 없습니다."
else
    CURRENT_SEMVER="$(extract_semver "$VERSION_RAW")"

    # 2) 패키지 관리자 및 최신 후보 버전 조회 (하드코딩 기준 제거)
    PM="unknown"
    if command -v apt-cache >/dev/null 2>&1; then
        PM="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PM="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PM="zypper"
    fi

    CANDIDATE_RAW=""
    PACKAGE_NAME=""

    case "$PM" in
        apt)
            for p in mysql-server mysql-community-server mysql-server-8.0; do
                c="$(run_cmd "apt-cache policy ${p} | awk '/Candidate:/{print \\\$2; exit}'")"
                if [[ -n "$c" && "$c" != "(none)" ]]; then
                    PACKAGE_NAME="$p"
                    CANDIDATE_RAW="$c"
                    break
                fi
            done
            ;;
        dnf)
            for p in mysql-community-server mysql-server; do
                c="$(run_cmd "dnf -q info ${p} | awk -F': ' '/^Version/{v=\\$2} /^Release/{r=\\$2} END{if(v!=""){print v"-"r}}'")"
                if [[ -n "$c" ]]; then
                    PACKAGE_NAME="$p"
                    CANDIDATE_RAW="$c"
                    break
                fi
            done
            ;;
        yum)
            for p in mysql-community-server mysql-server; do
                c="$(run_cmd "yum -q info ${p} | awk -F': ' '/^Version/{v=\\$2} /^Release/{r=\\$2} END{if(v!=""){print v"-"r}}'")"
                if [[ -n "$c" ]]; then
                    PACKAGE_NAME="$p"
                    CANDIDATE_RAW="$c"
                    break
                fi
            done
            ;;
        zypper)
            for p in mysql-community-server mysql-server; do
                c="$(run_cmd "zypper -q info ${p} | awk -F': ' '/^Version/{print \\\$2; exit}'")"
                if [[ -n "$c" ]]; then
                    PACKAGE_NAME="$p"
                    CANDIDATE_RAW="$c"
                    break
                fi
            done
            ;;
    esac

    CANDIDATE_SEMVER="$(extract_semver "$CANDIDATE_RAW")"

    if [[ -z "$CURRENT_SEMVER" ]]; then
        STATUS="FAIL"
        EVIDENCE="현재 MySQL 버전 문자열(${VERSION_RAW})에서 비교 가능한 버전 정보를 추출하지 못했습니다."
    elif [[ "$PM" == "unknown" || -z "$CANDIDATE_SEMVER" ]]; then
        STATUS="FAIL"
        EVIDENCE="현재 버전은 ${VERSION_RAW}(${CURRENT_SEMVER})로 확인되나, 패키지 저장소/벤더 채널에서 최신 후보 버전을 확인할 수 없어 D-25 판정을 완료하지 못했습니다."
    else
        if version_ge "$CURRENT_SEMVER" "$CANDIDATE_SEMVER"; then
            STATUS="PASS"
            EVIDENCE="현재 버전(${CURRENT_SEMVER})이 저장소 최신 후보(${CANDIDATE_SEMVER}, ${PM}/${PACKAGE_NAME}) 이상으로 확인되어 보안 패치 기준을 충족합니다."
        else
            STATUS="FAIL"
            EVIDENCE="현재 버전(${CURRENT_SEMVER})이 저장소 최신 후보(${CANDIDATE_SEMVER}, ${PM}/${PACKAGE_NAME})보다 낮아 보안 패치 적용이 필요합니다."
        fi
    fi
fi

# 파일 해시
if command -v mysqld >/dev/null 2>&1; then
    FILE_PATH=$(command -v mysqld)
    FILE_HASH=$(sha256sum "$FILE_PATH" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

IMPACT_LEVEL="HIGH"
ACTION_IMPACT="이 조치를 적용하면 MySQL을 최신 버전으로 업데이트하게 되므로, 기존 시스템에서 사용되던 애플리케이션, 스크립트, 드라이버 등과 호환성 문제가 발생할 수 있습니다. 따라서 업데이트 전에는 영향 범위를 충분히 검토하고, 테스트 환경에서 사전 검증을 수행한 후 운영 환경에 적용해야 합니다."

cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "현재 제품 버전(SELECT VERSION())과 벤더/저장소 최신 후보 버전을 비교해 주기적으로 보안 패치를 적용하세요. 참조: https://downloads.mysql.com/archives.php",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
