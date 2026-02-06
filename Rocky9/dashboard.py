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

# --- 2. 백엔드 실행 로직  ---
def run_remediation(target, check_id, action_type):
    """모든 하위 폴더에서 스크립트를 찾아 실행하고 결과를 업데이트함"""
    
    clean_id = check_id.replace("-", "")
    
    # glob을 사용하여 scripts 폴더 하위의 모든 곳에서 파일을 검색
    # **는 모든 하위 디렉토리를 의미하며, recursive=True가 필수입니다.
    search_pattern = f"./scripts/**/fix_{clean_id}.sh"
    found_files = glob.glob(search_pattern, recursive=True)

    if found_files:
        # 찾은 파일 중 첫 번째 경로를 사용
        script_path = found_files[0]
    else:
        st.error(f"스크립트 파일을 찾을 수 없습니다: fix_{clean_id}.sh")
        return False

    try:
        # 3. 스크립트 실행 (자동 조치 시 --force 인자 전달)
        cmd = ["sudo", "bash", script_path]
        if action_type == "auto":
            cmd.append("--force")
        
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode == 0:
            # 4. 실행 성공 시 해당 JSON 파일 업데이트
            result_file = f"./results/{target}_{check_id}.json"
            if os.path.exists(result_file):
                with open(result_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                data['status'] = "PASS"
                data['action_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                data['action_log'] = f"대시보드 조치 성공 (경로: {script_path})"
                
                with open(result_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=4)
            return True
        else:
            st.error(f"조치 실패: {process.stderr}")
            return False
            
    except Exception as e:
        st.error(f"백엔드 오류 발생: {e}")
        return False
    
# --- 3. 데이터 로드 및 엑셀 로직 ---
def load_all_data():
    results_path = "./results"
    all_data = []
    if os.path.exists(results_path):
        for file in os.listdir(results_path):
            if file.endswith(".json"):
                try:
                    with open(os.path.join(results_path, file), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data['target'] = file.split('_')[0]
                        if 'guide' not in data: data['guide'] = "보안 가이드를 참조하세요."
                        if 'action_type' not in data: data['action_type'] = "manual" 
                        all_data.append(data)
                except Exception as e: st.error(f"데이터 로드 오류: {e}")
    df = pd.DataFrame(all_data)
    if not df.empty:
        df = df.sort_values(by='check_id').reset_index(drop=True)
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

# 1. 사이드바 구성 (일괄 조치 기능 포함)
with st.sidebar:
    st.markdown("## 🛡️ Security Ops")
    if not df.empty:
        selected_target = st.selectbox("🎯 대상 서버 선택", sorted(df['target'].unique()))
        target_df = df[df['target'] == selected_target]
        
        st.divider()
        
        # --- [통합] 실무형 일괄 조치 로직 ---
        st.markdown("### ⚡ 운영 효율화")
        # 가용성 영향이 적은(auto) 항목 중 취약(FAIL)인 것들만 추출
        auto_fail_items = target_df[(target_df['action_type'] == 'auto') & (target_df['status'] == 'FAIL')]
        
        btn_label = f"🚀 자동 조치 ({len(auto_fail_items)}건) 일괄 실행"
        # 취약한 자동 조치 항목이 있을 때만 버튼 활성화
        if st.button(btn_label, type="primary", use_container_width=True, disabled=len(auto_fail_items)==0):
            success_count = 0
            p_bar = st.progress(0)
            p_text = st.empty()
            
            for idx, (_, row) in enumerate(auto_fail_items.iterrows()):
                p_text.text(f"조치 중: {row['check_id']}")
                if run_remediation(selected_target, row['check_id'], "auto"):
                    success_count += 1
                p_bar.progress((idx + 1) / len(auto_fail_items))
            
            p_text.empty()
            p_bar.empty()
            st.sidebar.success(f"✅ {success_count}개 항목 자동 조치 완료!")
            st.rerun() 
        
        st.divider()
        st.download_button("📊 엑셀 보고서 생성", to_excel(target_df), f"Report_{selected_target}.xlsx", use_container_width=True)
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
            
            if row['status'] == "PASS": item_c2.success("✅ 양호")
            else: item_c2.error("🚨 취약")
            
            # 조치 버튼 로직
            if row['status'] == "FAIL":
                if row['action_type'] == "manual":
                    if item_c3.button(f"⚠️ 승인 후 조치", key=f"btn_{row['check_id']}", use_container_width=True, type="secondary"):
                        st.session_state[f"modal_{row['check_id']}"] = True
                else:
                    if item_c3.button(f"🛠️ 즉시 조치", key=f"btn_{row['check_id']}", use_container_width=True, type="primary"):
                        with st.spinner(f"{row['check_id']} 조치 중..."):
                            if run_remediation(selected_target, row['check_id'], "auto"):
                                st.success("조치 성공!")
                                st.rerun() # 결과 즉시 반영

            # 수동 승인 모달 컨테이너
            if st.session_state.get(f"modal_{row['check_id']}", False):
                st.info(f"**고위험 항목 승인:** {row['title']}")
                st.error(f"**위험 알림:** {row['guide']}")
                m_c1, m_c2 = st.columns(2)
                if m_c1.button("✅ 승인 및 진행", key=f"conf_{row['check_id']}"):
                    with st.spinner("명령 실행 중..."):
                        if run_remediation(selected_target, row['check_id'], "manual"):
                            st.session_state[f"modal_{row['check_id']}"] = False
                            st.rerun()
                if m_c2.button("❌ 취소", key=f"canc_{row['check_id']}"):
                    st.session_state[f"modal_{row['check_id']}"] = False
                    st.rerun()

            st.markdown(f"**🔍 점검 근거:** `{row['evidence']}`")
            inner_c1, inner_c2 = st.columns(2)
            with inner_c1: st.markdown(f'📍 **법적 근거** <span class="tag tag-isms">ISMS-P</span> 2.1.2', unsafe_allow_html=True)
            with inner_c2: st.write(f"⚠️ **영향도:** {'신중 (수동)' if row['action_type'] == 'manual' else '낮음 (자동)'}")
            st.warning(f"💡 **조치 가이드:** {row['guide']}")
            st.divider()
