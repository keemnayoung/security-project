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
# @Platform : LINUX
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS 공유 설정이 적절히 제한되어 있는지 점검
# @Criteria_Good : 접근 통제 설정 및 /etc/exports 파일 권한 644인 경우
# @Criteria_Bad : 접근 통제 미설정 또는 파일 권한이 과다한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-40 NFS 접근 통제

# 1. 항목 정보 정의
ID="U-40"
CATEGORY="서비스관리"
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
    EVIDENCE="NFS exports 파일 없음 (NFS 미사용 - 양호)"
else
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    
    OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    
    # 소유자 root 확인
    if [ "$OWNER" != "root" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $TARGET_FILE 소유자 root 아님($OWNER);"
    fi
    
    # 권한 644 초과 확인
    if [ "$PERMS" -gt 644 ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $TARGET_FILE 권한 과다($PERMS>644);"
    fi
    
    # [Step 2] 공유 디렉터리에 접근할 수 있는 사용자 및 권한 확인
    # 가이드: cat /etc/exports
    CONTENT=$(grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -v "^$")
    if [ -n "$CONTENT" ]; then
        # everyone(*) 공유 확인 - 접근 통제 미설정
        if echo "$CONTENT" | grep -qE "\*\(|\s+\*$|\s+\*\s"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE 모든 호스트(*)에 공유 허용;"
        fi
    fi
    
    # 결과 판단
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="NFS 접근 통제 취약:$EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="NFS 접근 통제 설정 적절 (소유자:$OWNER, 권한:$PERMS)"
    fi
fi

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
    "guide": "/etc/exports에서 everyone(*) 공유 제거, no_root_squash를 root_squash로 변경 후 exportfs -ra로 적용하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
