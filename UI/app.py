import streamlit as st
import requests
import html

st.set_page_config(layout="wide")
st.title("🔐 Code Vulnerability Detection & Fix")

# --- Session state setup ---
defaults = {
    "code_submitted": False,
    "vuln_types": [],
    "vulnerable_lines": [],
    "show_fix": False,
    "suggested_fix": "",
    "lines_checked": False,
    "fix_checked": False,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# --- Fast Detection API (only vulnerability types) ---
def detect_fast():
    code_input = st.session_state.code_input.strip()
    if not code_input:
        st.session_state.code_submitted = False
        return

    try:
        response = requests.post("http://127.0.0.1:8000/detect-type", json={"code": code_input})
        if response.status_code == 200:
            data = response.json()
            st.session_state.vuln_types = data.get("vulnerability_types", [])
            st.session_state.code_submitted = True
            st.session_state.vulnerable_lines = []
            st.session_state.suggested_fix = ""
            st.session_state.lines_checked = False
            st.session_state.fix_checked = False
        else:
            st.error("❌ Detection error: " + response.text)
    except Exception as e:
        st.error(f"🚨 Exception during detection: {str(e)}")

# --- Layout with columns ---
col1, col2 = st.columns(2)

# --- Left Column: Code Input ---
with col1:
    st.text_area(
        "✍️ Enter your code snippet and press Enter:",
        height=400,
        key="code_input",
        on_change=detect_fast
    )

# --- Right Column: Output ---
with col2:
    if st.session_state.code_submitted:
        st.subheader("✅ Detected Vulnerabilities")
        if st.session_state.vuln_types:
            for v in st.session_state.vuln_types:
                st.markdown(f"- **{v}**")
        else:
            st.info("No known vulnerabilities detected.")

        # Vulnerable lines
        if not st.session_state.lines_checked:
            with st.spinner("🔍 Checking vulnerable lines..."):
                try:
                    response = requests.post("http://127.0.0.1:8000/detect-lines", json={
                        "code": st.session_state.code_input,
                        "vulnerability_types": st.session_state.vuln_types
                    })
                    if response.status_code == 200:
                        st.session_state.vulnerable_lines = response.json().get("vulnerable_lines", [])
                        st.session_state.lines_checked = True
                    else:
                        st.error("❌ Line detection error.")
                except Exception as e:
                    st.error(f"🚨 Exception during line detection: {str(e)}")

        if st.session_state.lines_checked and st.session_state.vulnerable_lines:
            st.subheader("⚠️ Vulnerable Code Highlight")
            code_lines = st.session_state.code_input.split("\n")
            for i, line in enumerate(code_lines, 1):
                if i in st.session_state.vulnerable_lines:
                    st.markdown(f"<span style='color:red;'>🔴 Line {i}: {html.escape(line)}</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span style='color:gray;'>Line {i}: {html.escape(line)}</span>", unsafe_allow_html=True)

        # Fix generation
        if not st.session_state.fix_checked:
            with st.spinner("💡 Generating fix..."):
                try:
                    response = requests.post("http://127.0.0.1:8000/fix", json={
                        "code": st.session_state.code_input,
                        "vulnerability_types": st.session_state.vuln_types
                    })
                    if response.status_code == 200:
                        st.session_state.suggested_fix = response.json().get("suggested_fix", "")
                        st.session_state.fix_checked = True
                        st.session_state.show_fix = True
                    else:
                        st.error("❌ Fix generation error.")
                except Exception as e:
                    st.error(f"🚨 Exception during fix generation: {str(e)}")

        if st.session_state.show_fix and st.session_state.suggested_fix:
            st.subheader("🛠️ Suggested Fix")
            st.code(st.session_state.suggested_fix)
    else:
        st.info("ℹ️ Enter your code and press Enter to detect vulnerabilities.")