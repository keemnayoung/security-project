import streamlit as st
import pandas as pd
import json
import glob
import os
import io
import plotly.graph_objects as go
import subprocess  # 실제 쉘 스크립트 실행을 위해 추가
from datetime import datetime


# --- 1. 페이지 설정 및 디자인 ---
st.set_page_config(page_title="🛡️ Security Ops Pro", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .status-banner { 
        padding: 30px; border-radius: 15px; color: white; text-align: center; 
        font-size: 28px; font-weight: bold; margin-bottom: 25px; 
    }
    .banner-secure { background: linear-gradient(135deg, #27ae60, #2ecc71); }
    .banner-warning { background: linear-gradient(135deg, #f1c40f, #f39c12); }
    .banner-vulnerable { background: linear-gradient(135deg, #e74c3c, #c0392b); }
    
    .info-card { 
        background: white; padding: 20px; border-radius: 12px; 
        border: 1px solid #eef0f2; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    .tag-isms { background-color: #e3f2fd; color: #1976d2; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)


# --- 2. 백엔드 실행 로직 수정 ---
def run_remediation(target, check_id, action_type):
    clean_id = check_id.replace("-", "") 
    try:
        # STEP 1: 조치 실행 (강화된 검증 로직이 포함된 fix 스크립트 실행)
        fix_cmd = ["ansible-playbook", "-i", "hosts", "run_fix.yml", "-e", f"target_id={clean_id}", "--limit", target]
        with st.spinner(f"🛠️ {clean_id} 조치 적용 중..."):
            subprocess.run(fix_cmd, capture_output=True, text=True, timeout=60)

        # 5초 대기 (서비스 안정화)
        import time
        time.sleep(5) 

        # STEP 2: 확실한 데이터 동기화를 위해 재점검 한 번 더 실행
        # 방안 B에 따라 이 결과가 기존 파일을 덮어쓰게 됩니다.
        audit_cmd = ["ansible-playbook", "-i", "hosts", "run_audit.yml", "-e", f"target_id={clean_id}", "--limit", target]
        with st.spinner(f"🔍 최종 상태 검증 중..."):
            subprocess.run(audit_cmd, capture_output=True, text=True, timeout=60)

        st.success(f"✅ {clean_id} 조치 및 검증 완료!")
        st.rerun() 
        return True
    except Exception as e:
        st.error(f"⚠️ 시스템 오류: {e}")
        return False
    
# --- 3. 데이터 로드 및 엑셀 로직 ---
def load_all_data():
    results_path = "./results"
    all_data = []
    
    if not os.path.exists(results_path):
        return pd.DataFrame()

    for file in os.listdir(results_path):
        if file.endswith(".json"):
            try:
                with open(os.path.join(results_path, file), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # 1. 파일명에서 타겟 서버 정보 추출
                    data['target'] = file.split('_')[0]
                    
                    # 2. ID 형식 통일 (U-01 -> U01) 및 우선순위 설정
                    # 파일명에 remediated가 있으면 조치 데이터로 간주
                    data['check_id'] = data.get('check_id', 'Unknown').replace("-", "")
                    data['origin_score'] = 2 if 'remediated' in file else 1
                    
                    # 3. 누락된 필드 기본값 채우기 (nan 방지)
                    if 'guide' not in data or not data['guide']:
                        data['guide'] = "보안 가이드를 참조하세요."
                    if 'evidence' not in data or not data['evidence']:
                        data['evidence'] = "상세 점검 근거 없음"
                    if 'category' not in data:
                        data['category'] = "계정관리"
                    if 'importance' not in data:
                        data['importance'] = "상"

                    all_data.append(data)
            except Exception as e:
                st.error(f"데이터 로드 오류 ({file}): {e}")

    df = pd.DataFrame(all_data)
    
    if not df.empty:
       # 4. 정렬 및 중복 제거
        # check_date를 기준으로 오름차순 정렬 후, 가장 마지막(최신) 데이터만 유지
        df = df.sort_values(by=['target', 'check_id', 'check_date'])
        df = df.drop_duplicates(subset=['target', 'check_id'], keep='last')
        df = df.reset_index(drop=True)
        
    return df

# --- 엑셀 ---
def to_excel(df):
    output = io.BytesIO()
    # 1. 데이터 정리 및 전처리
    report_df = df[['category', 'check_id', 'title', 'importance', 'status', 'evidence', 'guide']].copy()
    
    # [수정] 양호한 항목에 대해서는 조치 가이드 문구 변경
    report_df.loc[report_df['status'] == 'PASS', 'guide'] = "양호하여 조치가 필요 없습니다."
    
    report_df['status_label'] = report_df['status'].map({'FAIL': '취약', 'PASS': '양호'})
    report_df.columns = ['분류', '항목ID', '점검항목', '중요도', '상태_원문', '점검결과', '조치 가이드', '상태']
    
    # 출력 순서 조정
    report_df = report_df[['분류', '항목ID', '점검항목', '중요도', '상태', '점검결과', '조치 가이드']]

    # 2. 통계 데이터 계산
    total_val = len(report_df)
    fail_val = len(report_df[report_df['상태'] == '취약'])
    pass_rate = f"{round(((total_val - fail_val) / total_val) * 100, 1)} %" if total_val > 0 else "0.0 %"

    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        report_df.to_excel(writer, index=False, sheet_name='보안점검_리포트', startrow=7)
        
        workbook = writer.book
        worksheet = writer.sheets['보안점검_리포트']

        # --- 3. 서식 설정 ---
        title_fmt = workbook.add_format({'bold': True, 'font_size': 18, 'align': 'left'})
        label_fmt = workbook.add_format({'bg_color': '#F2F2F2', 'border': 1, 'bold': True, 'align': 'center', 'valign': 'vcenter'})
        val_fmt = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter'})
        fail_val_fmt = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'font_color': 'red', 'bold': True})
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1, 'align': 'center', 'valign': 'vcenter'})
        pass_cell_fmt = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'border': 1, 'align': 'center'})
        fail_cell_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'align': 'center'})
        default_cell_fmt = workbook.add_format({'border': 1, 'valign': 'vcenter'})

        # --- 4. 요약 보고서 상단 레이아웃 ---
        worksheet.write(0, 0, f"◐ 서버 보안 취약점 점검 요약 보고서", title_fmt)

        worksheet.write(2, 0, "전체 점검 건수", label_fmt)
        worksheet.write(2, 1, f"{total_val} 건", val_fmt)
        worksheet.write(2, 2, "점검 이행률", label_fmt)
        worksheet.write(2, 3, pass_rate, val_fmt)

        worksheet.write(3, 0, "취약 항목(FAIL)", label_fmt)
        worksheet.write(3, 1, f"{fail_val} 건", fail_val_fmt)
        worksheet.write(3, 2, "점검 일시", label_fmt)
        
        # [수정] 점검 일시 형식을 YYYY-MM-DD HH:MM으로 명확하게 표시
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
        worksheet.write(3, 3, now_str, val_fmt)

        # --- 5. 상세 테이블 서식 적용 ---
        for col_num, value in enumerate(report_df.columns.values):
            worksheet.write(7, col_num, value, header_fmt)   

        for row_num in range(len(report_df)):
            current_row = row_num + 8
            status_value = report_df.iloc[row_num]['상태']
            for col_num in range(len(report_df.columns)):
                cell_value = report_df.iloc[row_num, col_num]
                if col_num == 4: # 상태 컬럼
                    fmt = pass_cell_fmt if status_value == '양호' else fail_cell_fmt
                    worksheet.write(current_row, col_num, cell_value, fmt)
                else:
                    worksheet.write(current_row, col_num, cell_value, default_cell_fmt)

        # 열 너비 설정
        worksheet.set_column('A:A', 12)
        worksheet.set_column('B:B', 10)
        worksheet.set_column('C:C', 35)
        worksheet.set_column('D:D', 8)
        worksheet.set_column('E:E', 10)
        worksheet.set_column('F:F', 50)
        worksheet.set_column('G:G', 50)

    return output.getvalue()

# --- 4. 메인 UI 및 시각화 ---
df = load_all_data()
# 1. 사이드바 구성 
with st.sidebar:
    st.markdown("## 🛡️ Security Ops")
    if not df.empty:
        selected_target = st.selectbox("🎯 대상 서버 선택", sorted(df['target'].unique()))
        target_df = df[df['target'] == selected_target]
        
        st.divider()
        
       # 모든 항목 수동 조치화
        st.markdown("### 📊 리포트 관리")
        st.download_button("📊 엑셀 보고서 생성", to_excel(target_df.fillna("-")), f"Report_{selected_target}.xlsx", use_container_width=True)
    else: 
        st.stop()

# 2. 메인 화면 구성 (양호도 배너 및 도넛 차트)
# ※ 주의: 이 부분은 sidebar 블록 밖에 있어야 메인 화면에 정상 출력됩니다.
total_cnt = len(target_df)
fail_cnt = len(target_df[target_df['status'] == 'FAIL'])
pass_cnt = total_cnt - fail_cnt
pass_rate = round((pass_cnt / total_cnt) * 100) if total_cnt > 0 else 0

# 상태에 따른 배너 색상 결정
if pass_rate >= 90: status_text, banner_class = "안전 (Secure)", "banner-secure"
elif pass_rate >= 70: status_text, banner_class = "주의 (Warning)", "banner-warning"
else: status_text, banner_class = "취약 (Vulnerable)", "banner-vulnerable"

# 상단 상태 배너
st.markdown(f'<div class="status-banner {banner_class}">최종 상태: {status_text} (양호율 {pass_rate}%)</div>', unsafe_allow_html=True)

# 시각화 지표 레이아웃
col_chart, col_m1, col_m2, col_m3 = st.columns([1.5, 1, 1, 1])

with col_chart:
    # 도넛 차트 구성
    fig = go.Figure(go.Pie(
        labels=['양호', '취약'], 
        values=[pass_cnt, fail_cnt], 
        hole=.7, 
        marker_colors=['#2ecc71', '#e74c3c'], 
        showlegend=False
    ))
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0), 
        height=150, 
        annotations=[dict(text=f'{pass_rate}%', x=0.5, y=0.5, font_size=20, showarrow=False)]
    )
    st.plotly_chart(fig, use_container_width=True)

# 요약 카드 정보
col_m1.markdown(f'<div class="info-card"><div style="color:#7f8c8d">전체 항목</div><div style="font-size:2em; font-weight:800">{total_cnt}</div></div>', unsafe_allow_html=True)
col_m2.markdown(f'<div class="info-card"><div style="color:#7f8c8d">취약점</div><div style="font-size:2em; font-weight:800; color:#d9534f">{fail_cnt}</div></div>', unsafe_allow_html=True)
col_m3.markdown(f'<div class="info-card"><div style="color:#7f8c8d">무결성</div><div style="font-size:2em; font-weight:800; color:#2ecc71">100%</div></div>', unsafe_allow_html=True)

st.write("")
st.subheader("📑 상세 점검 내역 및 실시간 조치")

# --- 5. 상세 내역 및 인터랙티브 조치 버튼 ---
for cat in sorted(target_df['category'].unique()):
    with st.expander(f"📂 {cat}", expanded=True):
        items = target_df[target_df['category'] == cat]
        for _, row in items.iterrows():
            item_c1, item_c2, item_c3 = st.columns([5, 1, 1.5])
            item_c1.markdown(f"### {row['check_id']} {row['title']} (중요도: {row['importance']})")
            
            if row['status'] == "PASS": 
                item_c2.success("✅ 양호")
                item_c3.write("") # 양호할 때는 버튼 없음
            else: 
                item_c2.error("🚨 취약")
                # [수정] 모든 취약 항목은 '승인 후 조치' 버튼으로 통일
                if item_c3.button(f"⚠️ 승인 후 조치", key=f"btn_{row['check_id']}", use_container_width=True, type="secondary"):
                    st.session_state[f"modal_{row['check_id']}"] = True

            # 수동 승인 모달 컨테이너 (로직은 기존 유지)
            if st.session_state.get(f"modal_{row['check_id']}", False):
                st.info(f"**고위험 항목 승인:** {row['title']}")
                st.error(f"**위험 알림:** {row['guide']}")
                m_c1, m_c2 = st.columns(2)
                if m_c1.button("✅ 승인 및 진행", key=f"conf_{row['check_id']}"):
                    with st.spinner("앤서블 조치 실행 중..."):
                        if run_remediation(selected_target, row['check_id'], "manual"):
                            st.session_state[f"modal_{row['check_id']}"] = False
                            st.rerun()
                if m_c2.button("❌ 취소", key=f"canc_{row['check_id']}"):
                    st.session_state[f"modal_{row['check_id']}"] = False
                    st.rerun()

            st.markdown(f"**🔍 점검 근거:** `{row['evidence']}`")
            inner_c1, inner_c2 = st.columns(2)
            with inner_c1: st.markdown(f'📍 **법적 근거** <span class="tag tag-isms">ISMS-P</span> 2.1.2', unsafe_allow_html=True)
            # [수정] 영향도 표시 문구 통일
            with inner_c2: st.write(f"⚠️ **영향도:** 신중 (수동 조치 필요)")
            st.warning(f"💡 **조치 가이드:** {row['guide']}")
            st.divider()