#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Criteria_Good : 접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우
# @Criteria_Bad : 접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-40 NFS 접근 통제

# 1. 항목 정보 정의
ID="U-40"
CATEGORY="서비스 관리"
TITLE="NFS 접근 통제"
IMPORTANCE="상"
TARGET_FILE="/etc/exports"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [Step 1] 파일 소유자 및 권한 확인
# 가이드: ls -l /etc/exports (소유자 root, 권한 644)
if [ ! -f "$TARGET_FILE" ]; then
    STATUS="PASS"
    EVIDENCE="NFS exports 파일이 없습니다. (NFS 미사용 - 양호)"
else
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    
    OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    
    # 소유자 root 확인
    if [ "$OWNER" != "root" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $TARGET_FILE의 소유자가 root가 아닙니다. (현재: $OWNER)"
    fi
    
    # 권한 644 초과 확인
    if [ "$PERMS" -gt 644 ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $TARGET_FILE의 권한이 과대합니다. (현재: $PERMS)"
    fi
    
    # [Step 2] 공유 디렉터리에 접근할 수 있는 사용자 및 권한 확인
    # 가이드: cat /etc/exports
    CONTENT=$(grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -v "^$")
    if [ -n "$CONTENT" ]; then
        # everyone(*) 공유 확인 - 접근 통제 미설정
        if echo "$CONTENT" | grep -qE "\*\(|\s+\*$|\s+\*\s"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE 모든 호스트(*)에 대해 공유가 허용되어 있습니다."
        fi
    fi
    
    # 결과 판단
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="NFS 접근 통제가 미흡하여, 비인가 호스트에서 파일 시스템에 접근할 수 있는 위험이 있습니다. $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="NFS 접근 통제가 적절하게 설정되어 있습니다. (소유자: $OWNER, 권한: $PERMS)"
    fi
fi

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, NFS를 불가피하게 사용 중인 경우 허용 대상(사용자/호스트) 및 권한이 제한되면서 기존 접속 주체 중 일부가 접근하지 못할 수 있으므로, 운영에 필요한 허용 범위를 사전에 정의하고 단계적으로 반영해야 합니다."

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
    "guide": "/etc/exports에서 everyone(*) 공유를 제거하고, no_root_squash를 root_squash로 변경한 후 exportfs -ra로 적용해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
