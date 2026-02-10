import streamlit as st
import pandas as pd
import json
import os
import io
import subprocess
import time
from datetime import datetime

# --- 1. 페이지 설정 및 UI 디자인  ---
st.set_page_config(page_title="Security Ops Master v6.1", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
   <style>
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;600;800&display=swap');
    * { font-family: 'Pretendard', sans-serif; }

    .stApp { background-color: #F8FAFC; color: #1E293B; }

    /* 사이드바 배경 */
    [data-testid="stSidebar"] {
        background-color: white !important;
        border-right: 1px solid #E2E8F0;
    }

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

    
    /* 점검 카드 디자인 */
    .item-card {
        background: white; border-radius: 16px; padding: 25px; margin-bottom: 25px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.03); border: 1px solid #E2E8F0;
    }
    .border-pass { border-top: 8px solid #10B981 !important; }
    .border-vulnerable { border-top: 8px solid #EF4444 !important; }
    .border-manual {border-top: 5px solid #EF4444 !important; }

    /* --- 버튼 스타일 전체 수정 --- */
    .stButton > button {
        border-radius: 12px !important;
        font-weight: 700 !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
        border: none !important;
    }

    /* 1. 승인 완료 버튼  */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%) !important;
        color: white !important;
    }

    /* 2. 전 서버 점검 버튼  */
    button[key="sidebar_scan"] {
        background: #334155 !important;
        color: white !important;
    }

    /* 3. 개별 서버 점검 버튼 */
    button[key="single_server_scan"] {
        background: white !important;
        color: #1E293B !important;
        border: 1px solid #E2E8F0 !important;
    }
                

    /* 4. 보고서 다운로드 버튼  */
    .stDownloadButton > button {
        background-color: #1E293B !important;
        color: white !important;
        width: 100% !important;
        border-radius: 12px !important;
        border: none !important;
    }

    /* 5. 조치 시작 및 일반 버튼  */
    .stButton > button[kind="secondary"] {
        background-color: white !important;
        color: #475569 !important;
        border: 1px solid #E2E8F0 !important;
    }

    /* 버튼 호버 효과 */
    .stButton > button:hover, .stDownloadButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1) !important;
        filter: brightness(1.1) !important;
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
                    # check_id 시작 문자로 시스템/DB 분류
                    check_id = str(data.get('check_id', data.get('item_id', '')))
                    if 'D' in check_id.upper():
                        if "Rocky9" in data['target']:
                            data['db_type'] = "MySQL"
                        else:
                            data['db_type'] = "PostgreSQL"
                    else:
                        data['db_type'] = "OS"
                    
                    all_data.append(data)
            except:
                continue

    df = pd.DataFrame(all_data)
    if not df.empty:
        df = df.fillna("")
        df = df.replace([float('inf'), float('-inf')], 0)
        
        df['check_date'] = pd.to_datetime(df['check_date'], errors='coerce')
        df = df.sort_values(by=['target', 'check_id', 'check_date'], ascending=[True, True, False])
        df = df.drop_duplicates(subset=['target', 'check_id'], keep='first')
        df = df.sort_values(by='check_id')
        
    return df
# --- 3. 엑셀 출력 로직  ---
def to_excel(df):
    output = io.BytesIO()
    
    # 1. 데이터 클렌징 (보고서용 컬럼 추출 및 정리)
    # 필요한 컬럼이 없을 경우를 대비해 reindex 사용
    cols = ['category', 'check_id', 'title', 'importance', 'status', 'evidence', 'guide']
    report_df = df.reindex(columns=cols).fillna("N/A").copy()
    
    report_df.loc[report_df['status'] == 'PASS', 'guide'] = "조치가 필요 없습니다."
    report_df['status_label'] = report_df['status'].map({'FAIL': '취약', 'PASS': '양호'}).fillna('미점검')
    
    report_df.columns = ['분류', '항목ID', '점검항목', '중요도', '상태_원문', '점검결과', '조치 가이드', '상태']
    report_df = report_df[['분류', '항목ID', '점검항목', '중요도', '상태', '점검결과', '조치 가이드']]

    # 2. 요약 지표 계산 (분모 0 체크)
    total_val = len(report_df)
    fail_val = len(report_df[report_df['상태'] == '취약'])
    if total_val > 0:
        pass_rate = f"{round(((total_val - fail_val) / total_val) * 100, 1)} %"
    else:
        pass_rate = "0.0 %"

    # 3. 엑셀 파일 생성 (에러 방지 옵션 추가)
    # nan_inf_to_errors 옵션은 에러 대신 빈 값을 넣어줌
    with pd.ExcelWriter(output, engine='xlsxwriter', engine_kwargs={'options': {'nan_inf_to_errors': True}}) as writer:
        report_df.to_excel(writer, index=False, sheet_name='보안점검_리포트', startrow=7)
        
        workbook = writer.book
        worksheet = writer.sheets['보안점검_리포트']
        
        # 스타일 정의
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1, 'align': 'center'})
        pass_cell_fmt = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'border': 1, 'align': 'center'})
        fail_cell_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'align': 'center'})
        default_fmt = workbook.add_format({'border': 1})
        title_fmt = workbook.add_format({'bold': True, 'font_size': 18})

        # 상단 요약 정보 작성
        worksheet.write(0, 0, f"◐ 서버 보안 취약점 점검 요약 보고서", title_fmt)
        worksheet.write(2, 0, "전체 점검 건수"); worksheet.write(2, 1, f"{total_val} 건")
        worksheet.write(2, 2, "점검 이행률"); worksheet.write(2, 3, pass_rate)
        worksheet.write(3, 0, "취약 항목(FAIL)"); worksheet.write(3, 1, f"{fail_val} 건")
        worksheet.write(3, 2, "점검 일시"); worksheet.write(3, 3, datetime.now().strftime('%Y-%m-%d %H:%M'))

        # 데이터 본문 작성
        for col_num, value in enumerate(report_df.columns.values):
            worksheet.write(7, col_num, value, header_fmt)
            
        for row_num in range(len(report_df)):
            current_row = row_num + 8
            for col_num in range(len(report_df.columns)):
                cell_value = report_df.iloc[row_num, col_num]
                
                # [수정] 엑셀 쓰기 전 값이 숫자인지 체크하여 NaN이면 빈 문자열 처리
                if pd.isna(cell_value): cell_value = ""
                
                fmt = default_fmt
                if col_num == 4: # '상태' 컬럼 서식
                    fmt = pass_cell_fmt if cell_value == '양호' else fail_cell_fmt
                
                worksheet.write(current_row, col_num, cell_value, fmt)

        worksheet.set_column('A:G', 22)
        
    return output.getvalue()

# --- 4. 메인 데이터 로드 및 사이드바 ---
df = load_all_data()

with st.sidebar:
    st.markdown("## 🛡️ 제어 센터")
    
    # 전 서버 점검 버튼
    if st.button("🔍 전 서버 점검", key="sidebar_scan", use_container_width=True):
        with st.spinner("🚀 전체 서버 보안 점검 중..."):
            subprocess.run(["ansible-playbook", "-i", "hosts", "run_audit.yml"])
        st.rerun()

    st.divider()

    # 기본 서버 리스트 설정
    base_servers = ["Rocky9", "Rocky10"]
    # 실제 ./results 폴더에 있는 서버 이름들 추출 (없으면 빈 리스트)
    existing_servers = df['target'].unique().tolist() if not df.empty else []
    # 기본 리스트와 실제 리스트를 합친 후 중복 제거 + 역순 정렬 (Rocky9 우선)
    server_list = sorted(list(set(base_servers + existing_servers)), reverse=True)
    # 이제 항상 Rocky9, Rocky10이 모두 들어있는 리스트가 보입니다.
    selected_target = st.selectbox("🎯 대상 서버 선택", server_list, key="main_target_select")

    
    if st.button(f"⚡ {selected_target} 서버만 점검", key="single_server_scan", use_container_width=True):
        with st.spinner(f"🔍 {selected_target} 보안 점검 중..."):
            subprocess.run(["ansible-playbook", "-i", "hosts", "run_audit.yml", "--limit", selected_target])
        st.success(f"✔️ {selected_target} 점검이 완료되었습니다!")
        time.sleep(1) 
        st.rerun()
    
    st.divider()

    # 보고서 다운로드와 메인 화면 중단 로직
    if not df.empty:
        target_df = df[df['target'] == selected_target].reset_index(drop=True)
        st.download_button("📊 보고서 다운로드", to_excel(target_df), f"Report_{selected_target}.xlsx", use_container_width=True)
    else:
        
        st.stop()

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

# --- 7. 카드 렌더링 함수 ---
def draw_security_cards(data):
    if data.empty:
        st.info("💡 해당하는 점검 항목이 없습니다.")
        return

    category_order = [
        "계정관리",           # 1_account
        "파일 및 디렉토리 관리", # 2_directory
        "서비스 관리",         # 3_service
        "패치 관리",           # 4_patch
        "로그 관리"            # 5_log
    ]
   # 2. 실제 데이터의 카테고리를 기준 리스트 순서에 맞게 정렬
    existing_cats = [cat for cat in category_order if cat in data['category'].unique()]
    other_cats = sorted([cat for cat in data['category'].unique() if cat not in category_order])
    final_cats = existing_cats + other_cats

    # 3. sorted(...) 대신 위에서 만든 final_cats로 루프 돌리기
    for cat in final_cats:
        cat_items = data[data['category'] == cat].sort_values('check_id').reset_index(drop=True)
        fail_count = len(cat_items[cat_items['status'] == 'FAIL'])
        
        border_color = "#EF4444" if fail_count > 0 else "#10B981"
        bg_color = "#FFF5F5" if fail_count > 0 else "#F0FDF4"
        text_color = "#C53030" if fail_count > 0 else "#15803D"
        icon = "⚠️" if fail_count > 0 else "✅"
        status_label = f"취약 {fail_count}건" if fail_count > 0 else "보안 양호"

        st.markdown(f"""
            <style>
            div[data-testid="stExpander"] {{
                border: none !important;
                background: transparent !important;
                box-shadow: none !important;
                margin-top: -72px !important; 
                padding: 0 !important;
            }}
            div[data-testid="stExpander"] > details {{
                border: none !important;
                box-shadow: none !important;
            }}
            div[data-testid="stExpander"] details[open] > div {{
                border: none !important;
                padding-top: 20px !important;
            }}
            div[data-testid="stExpander"] summary {{
                height: 72px !important;
                color: transparent !important;
                list-style: none !important;
                padding: 0 !important;
            }}
            div[data-testid="stExpander"] summary::-webkit-details-marker {{
                display: none !important;
            }}
            </style>
            
            <div style="
                background-color: white; 
                padding: 18px 25px; 
                border-radius: 15px; 
                /* [수정] 왼쪽 바(border-left)를 삭제하고 전체 테두리만 연하게 추가 */
                border: 1px solid #E2E8F0; 
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: relative;
                z-index: 10;
                pointer-events: none;
            ">
                <div style="font-size: 1.25rem; font-weight: 800; color: #1E293B; display: flex; align-items: center;">
                    📂 {cat}
                </div>
                <div style="background-color: {bg_color}; color: {text_color}; padding: 5px 16px; border-radius: 50px; font-size: 0.95rem; font-weight: 800; border: 1px solid {border_color}44;">
                    {icon} {status_label}
                </div>
            </div>
            """, unsafe_allow_html=True)

        with st.expander("", expanded=False):
            # 카드가 닫혀있을 땐 아무것도 안 보이고, 열릴 때만 아래 패딩 추가
            st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
            for i, row in cat_items.iterrows():
                # 변수 가져오기 및 display_text 결정
                action_result = row.get('action_result', '')
                action_log = row.get('action_log', '')
                evidence = row.get('evidence', '')
                is_pass = row['status'] == 'PASS'
                # PARTIAL_SUCCESS 여부 확인
                is_manual_target = (action_result == 'PARTIAL_SUCCESS')

                if is_pass:
                    card_cls = "border-pass"
                elif is_manual_target:
                    card_cls = "border-manual" # 노란색 테두리 (CSS 정의 필요)
                else:
                    card_cls = "border-vulnerable"
                
                # [수정] PARTIAL_SUCCESS인 경우 action_log(수동 조치 가이드)를 최우선으로 표시
                if is_manual_target and action_log:
                    display_text = action_log
                elif action_result == 'SUCCESS' and action_log:
                    display_text = action_log
                elif evidence:
                    display_text = evidence
                else:
                    display_text = "상세 데이터가 없습니다."

                # 가이드/알림 박스
                # 가이드/알림 박스 (중복 생성을 막기 위해 elif로 연결)
                guide_html = ""
                
                # 1. 수동 조치 대상인 경우 (노란색)
                if is_manual_target:
                    guide_html = f'<div style="background:#FFFBEB; padding:18px; border-radius:12px; border:1px solid #FDE68A; margin-top:15px; color:#92400E;">⚠️ <b>수동 조치 안내:</b> {row["guide"]}</div>'
                
                # 2. 일반 취약 상태인 경우 (빨간색)
                elif not is_pass:
                    guide_html = f'<div style="background:#FFF5F5; padding:18px; border-radius:12px; border:1px solid #FED7D7; margin-top:15px; color:#C53030;">💡 <b>조치 가이드:</b> {row["guide"]}</div>'
                
                # 3. 조치 완료 상태인 경우 (초록색)
                elif row.get('action_result') == 'SUCCESS':
                    guide_html = f'<div style="background:#F0FDF4; padding:18px; border-radius:12px; border:1px solid #BBF7D0; margin-top:15px; color:#15803D;">✅ <b>조치 완료:</b> {row["guide"]}</div>'
               

                # 메인 카드 출력 
                st.markdown(f"""
                    <div class="item-card {card_cls}">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <span class="badge">중요도: {row['importance']}</span>
                                <span class="badge">ISMS-P 2.1.2</span>
                                <h2 style="margin: 15px 0; font-size: 1.6rem; letter-spacing:-0.5px;">
                                    <span style="color:#64748B; margin-right:10px;"></span> {row['check_id']} {row['title']}
                                </h2>
                                <p style="font-size: 1.1rem; color: #475569;">🔍 <b>점검 결과:</b> {display_text}</p>
                            </div>
                            <div class="{'status-secure' if is_pass else 'status-vulnerable'}"
                            style="margin-top: -10px; font-weight: bold; font-size: 1.2rem;">
                                ● {'양호' if is_pass else '취약'}
                            </div>
                        </div>
                        {guide_html}
                    </div>
                """, unsafe_allow_html=True)
                
                if not is_pass:
                    # 현재 항목이 조치 모드인지 확인
                    is_fixing = st.session_state.get(f"confirm_{row['check_id']}", False)

                    # 1. 수동 조치 대상이면 안내만 띄우고 버튼은 아예 생략
                    if is_manual_target:
                        st.info("💡**이 항목은 관리자의 수동 조치가 필요합니다.** 상단 가이드를 확인해 주세요.")
                    
                    # 2. 수동 조치가 아니고, 아직 '조치 시작' 버튼을 안 눌렀을 때
                    elif not is_fixing:
                        if st.button(f"⚡ {row['check_id']} 조치 프로세스 시작", key=f"pre_fix_{row['check_id']}", use_container_width=True):
                            st.session_state[f"confirm_{row['check_id']}"] = True
                            st.rerun()
                    
                    # 3. 조치 시작을 눌러서 승인 단계로 넘어왔을 때
                    else:
                        impact_text = row.get('action_impact', '일반적인 경우 영향이 없습니다.')
                        impact_level = row.get('impact_level', 'LOW')
      
                        # 영향도 안내 UI (사용자가 안심할 수 있게 시각화)
                        if impact_level == "LOW":
                            st.markdown(f"""
                                <div style="background-color: #F0FDF4; padding: 16px; border-radius: 8px; border: 1px solid #BBF7D0; margin-bottom: 20px;">
                                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                        <span style="background-color: #22C55E; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 10px;">SAFE</span>
                                        <b style="color: #166534; font-size: 1.05rem;">🛡️ 안전한 조치 안내</b>
                                    </div>
                                    <p style="margin: 0; color: #166534; line-height: 1.6;">{impact_text}</p>
                                </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                                <div style="background-color: #FFFBEB; padding: 16px; border-radius: 8px; border: 1px solid #FDE68A; margin-bottom: 20px;">
                                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                        <span style="background-color: #F59E0B; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 10px;">CAUTION</span>
                                        <b style="color: #92400E; font-size: 1.05rem;">⚠️ 조치 시 주의사항</b>
                                    </div>
                                    <p style="margin: 0; color: #92400E; line-height: 1.6;">{impact_text}</p>
                                </div>
                            """, unsafe_allow_html=True)

                        # 3. 승인 안내 문구 (버튼 바로 위로 이동)
                        st.info("💡 **운영 영향도 검토 및 보안 담당자의 최종 승인**을 완료하셨습니까?")
                        
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("✅ 승인 완료 (실행)", key=f"final_fix_{row['check_id']}", type="primary", use_container_width=True):
                                with st.spinner(f"🛠️ {row['check_id']} 조치 중..."):
                                    # 앤서블 실행
                                    subprocess.run(["ansible-playbook", "-i", "hosts", "run_fix.yml", "-e", f"target_id={row['check_id'].replace('-','')}", "--limit", selected_target])
                                    time.sleep(1)
                                st.success(f"✔️ {row['check_id']} 조치 완료!")
                                st.session_state[f"confirm_{row['check_id']}"] = False
                                st.rerun()
                        with c2:
                            if st.button("❌ 취소", key=f"cancel_{row['check_id']}", use_container_width=True):
                                st.session_state[f"confirm_{row['check_id']}"] = False
                                st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

with tab_os:
    # selected_target 변수를 사용하여 현재 선택된 서버 이름(Rocky9 등)이 제목에 표시됩니다.
    st.markdown(f"### 💻 {selected_target} 보안 점검 결과")
    draw_security_cards(target_df[target_df['db_type'] == "OS"])

with tab_db:
    if "Rocky9" in selected_target:
        db_label = "MySQL"
    elif "Rocky10" in selected_target:
        db_label = "PostgreSQL"
    else:
        db_label = "Database"

    st.markdown(f"### 🗄️ {db_label} 보안 점검 결과")
    
    # DB 관련 데이터(D-로 시작하는 항목) 필터링해서 출력
    db_items = target_df[target_df['db_type'].isin(["MySQL", "PostgreSQL"])]
    
    if db_items.empty:
        st.info("💡 해당하는 점검 항목이 없습니다.")
    else:
        draw_security_cards(db_items)