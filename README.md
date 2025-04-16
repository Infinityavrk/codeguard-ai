# 🔐 Code Vulnerability Detection & Fix (Streamlit App)

This Streamlit-based web application allows you to:

- Detect code vulnerabilities (like SQL Injection, CSRF)
- Highlight vulnerable lines
- Get suggested fixes for detected issues

---

## 📦 Requirements

- Python 3.8+
- Install dependencies via:

```bash
pip install -r requirements.txt
```

---

## 🛠 Installation

```bash
git clone https://github.com/your-repo/vuln-detect-app.git
cd vuln-detect-app
pip install -r requirements.txt
```

---

## 🚀 Running the App

Make sure your **FastAPI backend is running** at `http://127.0.0.1:8000`

Then launch the frontend with:

```bash
streamlit run app.py
```

---

## 📌 Features

- 🧠 ML-powered multi-label vulnerability detection
- ⚠️ Line-level vulnerability highlights
- 💡 Fix suggestion with one click

---

## 📷 Screenshot

_You can include a screenshot here by adding `screenshot.png` in your repo and using:_

```markdown
![App Screenshot](screenshot.png)
```

---

## 📝 Notes

- Ensure the FastAPI backend is active before submitting code.
- This version does **not include PDF export** — only HTML rendering and fix suggestion are enabled.

---

## 📫 Contact

Maintained by **Asha Vidyadharan**

Feel free to reach out for contributions or suggestions!