import streamlit as st
import pandas as pd
import json
import os
import io
import subprocess
import time
from datetime import datetime

# --- 1. 페이지 설정 및 UI 디자인 (디자인 및 색상 복구) ---
st.set_page_config(page_title="Security Ops Master v6.1", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;600;800&display=swap');
    * { font-family: 'Pretendard', sans-serif; }

    .stApp { background-color: #F8FAFC; color: #1E293B; }

    /* 상단 지표 카드 */
    .metric-container { display: flex; gap: 20px; margin-bottom: 30px; }
    .metric-card {
        background: white; padding: 25px; border-radius: 20px; flex: 1;
        box-shadow: 0 4px 15px rgba(0,0,0,0.05); border: 1px solid #E2E8F0; text-align: center;
    }
    .metric-value { font-size: 2.2rem; font-weight: 800; margin: 10px 0; }
    
    .status-secure { color: #10B981 !important; font-weight: 800; font-size: 1.3rem; }
    .status-vulnerable { color: #EF4444 !important; font-weight: 800; font-size: 1.3rem; }

    .badge {
        padding: 5px 14px; border-radius: 50px; font-weight: 700; font-size: 0.85rem;
        background: #F1F5F9; color: #475569; border: 1px solid #E2E8F0; margin-right: 5px;
    }

    .item-card {
        background: white; border-radius: 16px; padding: 25px; margin-bottom: 25px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.04); border: 1px solid #E2E8F0;
    }
    .border-pass { border-top: 8px solid #10B981 !important; }
    .border-vulnerable { border-top: 8px solid #EF4444 !important; }

    .stButton > button { border-radius: 10px; font-weight: 700; }
    .fix-btn > div > button {
        background-color: #F97316 !important; color: white !important;
        border: none !important; padding: 10px 20px !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- 2. 데이터 로드 로직 ---
def load_all_data():
    results_path = "./results"
    all_data = []
    if not os.path.exists(results_path): return pd.DataFrame()

    for file in os.listdir(results_path):
        if file.endswith(".json"):
            try:
                with open(os.path.join(results_path, file), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 파일명에서 타겟 정보 추출
                    data['target'] = file.split('_')[0]
                    
                    # db_type 분류 로직 (기존 유지)
                    path = data.get('path', '').lower()
                    data['db_type'] = "MySQL" if "mysql" in path else "PostgreSQL" if "postgres" in path else "OS"
                    
                    all_data.append(data)
            except:
                continue

    df = pd.DataFrame(all_data)
    if not df.empty:
        df = df.fillna("")
        
        df['check_date'] = pd.to_datetime(df['check_date'], errors='coerce')
        df = df.sort_values(by=['target', 'check_id', 'check_date'], ascending=[True, True, False])
        df = df.drop_duplicates(subset=['target', 'check_id'], keep='first')
        df = df.sort_values(by='check_id')
        
    return df
# --- 3. 엑셀 출력 로직  ---
def to_excel(df):

    output = io.BytesIO()
    report_df = df[['category', 'check_id', 'title', 'importance', 'status', 'evidence', 'guide']].copy()
    report_df.loc[report_df['status'] == 'PASS', 'guide'] = "조치가 필요 없습니다."
    report_df['status_label'] = report_df['status'].map({'FAIL': '취약', 'PASS': '양호'})
    report_df.columns = ['분류', '항목ID', '점검항목', '중요도', '상태_원문', '점검결과', '조치 가이드', '상태']
    report_df = report_df[['분류', '항목ID', '점검항목', '중요도', '상태', '점검결과', '조치 가이드']]

    total_val = len(report_df)
    fail_val = len(report_df[report_df['상태'] == '취약'])
    pass_rate = f"{round(((total_val - fail_val) / total_val) * 100, 1)} %" if total_val > 0 else "0.0 %"

    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        report_df.to_excel(writer, index=False, sheet_name='보안점검_리포트', startrow=7)
        workbook = writer.book
        worksheet = writer.sheets['보안점검_리포트']
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1, 'align': 'center'})
        pass_cell_fmt = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'border': 1, 'align': 'center'})
        fail_cell_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'align': 'center'})
        default_fmt = workbook.add_format({'border': 1})
        title_fmt = workbook.add_format({'bold': True, 'font_size': 18})

        worksheet.write(0, 0, f"◐ 서버 보안 취약점 점검 요약 보고서", title_fmt)
        worksheet.write(2, 0, "전체 점검 건수"); worksheet.write(2, 1, f"{total_val} 건")
        worksheet.write(2, 2, "점검 이행률"); worksheet.write(2, 3, pass_rate)
        worksheet.write(3, 0, "취약 항목(FAIL)"); worksheet.write(3, 1, f"{fail_val} 건")
        worksheet.write(3, 2, "점검 일시"); worksheet.write(3, 3, datetime.now().strftime('%Y-%m-%d %H:%M'))


        for col_num, value in enumerate(report_df.columns.values):
            worksheet.write(7, col_num, value, header_fmt)
        for row_num in range(len(report_df)):
            current_row = row_num + 8
            for col_num in range(len(report_df.columns)):
                cell_value = report_df.iloc[row_num, col_num]
                fmt = default_fmt
                if col_num == 4: fmt = pass_cell_fmt if cell_value == '양호' else fail_cell_fmt
                worksheet.write(current_row, col_num, cell_value, fmt)

        worksheet.set_column('A:G', 20)
    return output.getvalue()

# --- 4. 메인 데이터 로드 및 사이드바 ---
df = load_all_data()

with st.sidebar:
    st.markdown("## 🛡️ 제어 센터")
    if st.button("🔍 전 서버 점검", key="sidebar_scan", use_container_width=True, type="primary"):
        subprocess.run(["ansible-playbook", "-i", "hosts", "run_audit.yml"])
        st.rerun()
    st.divider()
    if not df.empty:
        selected_target = st.selectbox("🎯 대상 서버 선택", sorted(df['target'].unique()), key="main_target_select")
        target_df = df[df['target'] == selected_target].reset_index(drop=True)
        # 📊 보고서 다운로드 버튼 복구
        st.download_button("📊 보고서 다운로드", to_excel(target_df), f"Report_{selected_target}.xlsx", use_container_width=True)
    else: st.stop()

# --- 5. 보안 지표 계산 ---
def get_metrics(data):
    weights = {'상': 5, '중': 3, '하': 1}
    data['weight'] = data['importance'].map(lambda x: weights.get(x, 1))
    total_w = data['weight'].sum()
    pass_w = data[data['status'] == 'PASS']['weight'].sum()
    score = (pass_w / total_w * 100) if total_w > 0 else 0
    grade = "A" if score >= 90 else "B" if score >= 80 else "F"
    vuln_count = len(data[data['status'] != 'PASS'])
    
    integrity_items = data[data.get('file_hash', '') != ""]
    integrity = (len(integrity_items[integrity_items['status'] == 'PASS']) / len(integrity_items) * 100) if not integrity_items.empty else score
    return score, grade, vuln_count, integrity

score, grade, vuln_count, integrity = get_metrics(target_df)

# --- 6. 상단 지표 레이아웃 ---
st.markdown(f"""
    <div class="metric-container">
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">보안 양호도 등급</div>
            <div class="metric-value {'grade-a' if score>=85 else 'grade-f'}">{grade} <span style="font-size:1.1rem; color:#94A3B8;">({score:.1f}%)</span></div>
        </div>
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">취약점 탐지</div>
            <div class="metric-value" style="color:#EF4444;">{vuln_count} <span style="font-size:1rem;">건</span></div>
        </div>
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">시스템 무결성 지수</div>
            <div class="metric-value" style="color:#3B82F6;">{integrity:.1f}%</div>
        </div>
    </div>
""", unsafe_allow_html=True)

tab_os, tab_db = st.tabs(["💻 리눅스 서버 보안", "🗄️ 데이터베이스 보안"])

# --- 7. 카드 렌더링 함수 (디자인 복구 완료) ---
def draw_security_cards(data):
    if data.empty:
        st.info("💡 해당하는 점검 항목이 없습니다.")
        return
        
    for cat in sorted(data['category'].unique()):
        with st.expander(f"📂 {cat}", expanded=True):
            cat_items = data[data['category'] == cat].sort_values('check_id').reset_index(drop=True)
            
            for i, row in cat_items.iterrows():
                is_pass = row['status'] == 'PASS'
                card_cls = "border-pass" if is_pass else "border-vulnerable"
                
                # 변수 가져오기 및 display_text 결정 (action_log 우선)
                action_result = row.get('action_result', '')
                action_log = row.get('action_log', '')
                evidence = row.get('evidence', '')

                if action_result == 'SUCCESS' and action_log:
                    display_text = action_log
                elif evidence:
                    display_text = evidence
                else:
                    display_text = "상세 데이터가 없습니다."
                
                # 가이드/알림 박스
                guide_html = ""
                if not is_pass:
                    guide_html = f'<div style="background:#FFF5F5; padding:18px; border-radius:12px; border:1px solid #FED7D7; margin-top:15px; color:#C53030;">💡 <b>조치 가이드:</b> {row["guide"]}</div>'
                elif row.get('action_result') == 'SUCCESS':
                    guide_html = f'<div style="background:#F0FDF4; padding:18px; border-radius:12px; border:1px solid #BBF7D0; margin-top:15px; color:#15803D;">✅ <b>조치 완료:</b> {row["guide"]}</div>'

                # 메인 카드 출력 (디자인 복구)
                st.markdown(f"""
                    <div class="item-card {card_cls}">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <span class="badge">중요도: {row['importance']}</span>
                                <span class="badge">ISMS-P 2.1.2</span>
                                <h2 style="margin: 15px 0; font-size: 1.6rem; letter-spacing:-0.5px;">
                                    <span style="color:#64748B; margin-right:10px;">{i+1}.</span> {row['check_id']} {row['title']}
                                </h2>
                                <p style="font-size: 1.1rem; color: #475569;">🔍 <b>점검 결과:</b> {display_text}</p>
                            </div>
                            <div class="{'status-secure' if is_pass else 'status-vulnerable'}">
                                ● {'양호' if is_pass else '취약'}
                            </div>
                        </div>
                        {guide_html}
                    </div>
                """, unsafe_allow_html=True)
                
                if not is_pass:
                    # 현재 항목이 조치 모드인지 확인
                    is_fixing = st.session_state.get(f"confirm_{row['check_id']}", False)

                    if not is_fixing:
                        # 1단계: 조치 시작 버튼 (누르면 사라짐)
                        if st.button(f"⚡ {row['check_id']} 조치 프로세스 시작", key=f"pre_fix_{row['check_id']}", use_container_width=True):
                            st.session_state[f"confirm_{row['check_id']}"] = True
                            st.rerun() # 상태 반영을 위해 즉시 새로고침
                    else:
                        # 2단계: 보안 관리자 승인 안내 및 승인/취소 버튼
                        st.info("💡 **운영 영향도 검토 및 보안 담당자의 최종 승인**을 완료하셨습니까?")
                        st.warning(f"⚠️ **[안전 장치]** {row['check_id']} 조치를 실제로 수행하시겠습니까?")
                        
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("✅ 승인 완료 (실행)", key=f"final_fix_{row['check_id']}", type="primary", use_container_width=True):
                                with st.spinner(f"🛠️ {row['check_id']} 조치 중..."):
                                    # 앤서블 실행
                                    subprocess.run(["ansible-playbook", "-i", "hosts", "run_fix.yml", "-e", f"target_id={row['check_id'].replace('-','')}", "--limit", selected_target])
                                    time.sleep(1)
                                st.success(f"✔️ {row['check_id']} 조치 완료!")
                                # 조치 완료 후 상태 초기화 및 새로고침
                                st.session_state[f"confirm_{row['check_id']}"] = False
                                st.rerun()
                        with c2:
                            if st.button("❌ 취소", key=f"cancel_{row['check_id']}", use_container_width=True):
                                st.session_state[f"confirm_{row['check_id']}"] = False
                                st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

with tab_os:
    draw_security_cards(target_df[target_df['db_type'] == "OS"])

with tab_db:
    current_db = "MySQL" if "Target-01" in selected_target else "PostgreSQL"
    st.markdown(f"## 🛠️ {current_db} 전용 보안 점검 항목")
    draw_security_cards(target_df[target_df['db_type'] != "OS"])