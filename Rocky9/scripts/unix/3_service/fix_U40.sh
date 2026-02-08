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
# @Platform : LINUX
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS 공유 설정을 적절히 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-40 NFS 접근 통제

# 1. 항목 정보 정의
ID="U-40"
CATEGORY="서비스관리"
TITLE="NFS 접근 통제"
IMPORTANCE="상"
TARGET_FILE="/etc/exports"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

if [ ! -f "$TARGET_FILE" ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="NFS exports 파일이 없음"
else
    # [Step 1] 조치 전 상태 확인
    BEFORE_OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    BEFORE_PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    BEFORE_SETTING="소유자:$BEFORE_OWNER 권한:$BEFORE_PERMS"
    
    # [Step 3] 파일 소유자를 root로 변경
    # 가이드: chown root /etc/exports
    chown root "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 소유자 root로 변경;"
    
    # [Step 4] 파일 권한을 644로 변경
    # 가이드: chmod 644 /etc/exports
    chmod 644 "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 권한 644로 변경;"
    
    # [Step 5] 디렉터리 공유 설정은 수동 확인 필요
    # 가이드: /home/example host1 (ro, root_squash)
    # everyone(*) 공유가 있으면 경고 메시지 출력
    if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "\*\(|\s+\*$|\s+\*\s"; then
        ACTION_LOG="$ACTION_LOG [주의] everyone(*) 공유 설정 발견 - 수동 확인 필요;"
    fi
    
    # [Step 6] NFS 서비스 설정 적용
    # 가이드: exportfs -ra
    exportfs -ra 2>/dev/null
    ACTION_LOG="$ACTION_LOG exportfs -ra 실행;"
    
    AFTER_OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    AFTER_PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    AFTER_SETTING="소유자:$AFTER_OWNER 권한:$AFTER_PERMS"
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
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
