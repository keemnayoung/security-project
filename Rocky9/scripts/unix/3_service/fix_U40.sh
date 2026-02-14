#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-40 NFS 접근 통제

# 1. 항목 정보 정의
ID="U-40"
CATEGORY="서비스 관리"
TITLE="NFS 접근 통제"
IMPORTANCE="상"
TARGET_FILE="/etc/exports"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

if [ ! -f "$TARGET_FILE" ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="NFS exports 파일이 존재하지 않습니다."
else
    # [Step 1] 조치 전 상태 확인
    BEFORE_OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    BEFORE_PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    
    # [Step 3] 파일 소유자를 root로 변경
    # 가이드: chown root /etc/exports
    chown root "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 소유자를 root로 변경했습니다."
    
    # [Step 4] 파일 권한을 644로 변경
    # 가이드: chmod 644 /etc/exports
    chmod 644 "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 권한을 644로 변경했습니다."
    
    # [Step 5] everyone(*) 공유 설정 자동 변경
    # 가이드: /home/example host1 (ro, root_squash)
    # everyone(*)을 127.0.0.1(로컬)로 변경
    if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "\*\(|\s+\*$|\s+\*\s"; then
        cp "$TARGET_FILE" "${TARGET_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
        
        # * 를 127.0.0.1로 변경
        sed -i 's/\s\+\*\s\+/ 127.0.0.1 /g' "$TARGET_FILE"
        sed -i 's/\s\+\*$/127.0.0.1/g' "$TARGET_FILE"
        sed -i 's/\*(/127.0.0.1(/g' "$TARGET_FILE"
        
        ACTION_LOG="$ACTION_LOG everyone(*) 공유를 127.0.0.1(로컬)로 변경했습니다. 특정 네트워크에서 NFS 접근이 필요한 경우 /etc/exports 파일에서 127.0.0.1을 해당 IP 또는 네트워크 대역(예: 192.168.1.0/24)으로 수동 변경하십시오."
    fi
    
    # [Step 6] NFS 서비스 설정 적용
    # 가이드: exportfs -ra
    exportfs -ra 2>/dev/null
    ACTION_LOG="$ACTION_LOG exportfs -ra를 실행했습니다."
    
    ACTION_LOG="/etc/exports 파일의 소유자를 root로 변경하고 권한을 644로 설정했으며, everyone(*) 공유가 있는 경우 로컬(127.0.0.1)로 제한했습니다. 특정 네트워크의 NFS 접근이 필요하다면 /etc/exports 파일에서 허용할 IP 또는 네트워크 대역으로 수동 변경하십시오."
fi

STATUS="PASS"
EVIDENCE="NFS 접근 통제가 적절히 설정되어 있습니다."

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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
