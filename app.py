import streamlit as st

from database import get_dashboard_data, initialize_database, save_investigation
from detector import analyze_email


st.set_page_config(page_title="LS CyberShield | SOC Email Triage", page_icon="🛡️", layout="wide")
initialize_database()

st.markdown(
    """
    <style>
    :root {
        color-scheme: light;
        --ink: #172b4d;
        --muted-ink: #43546b;
        --line: #cbd5e1;
        --surface: #ffffff;
        --canvas: #f1f5f9;
        --accent: #075985;
    }
    .stApp, [data-testid="stAppViewContainer"] {
        background: var(--canvas);
        color: var(--ink);
    }
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1440px; }
    .stMarkdown, .stMarkdown p, .stMarkdown li, [data-testid="stCaption"],
    [data-testid="stWidgetLabel"] p, label, small {
        color: var(--ink);
    }
    [data-testid="stCaption"] { color: var(--muted-ink); }
    h1, h2, h3, h4, h5, h6 { color: #102a43; }
    .eyebrow { color: #67e8f9; font-size: .78rem; font-weight: 700; letter-spacing: .13em; }
    .hero {
        background: linear-gradient(115deg, #102a43, #164e63);
        color: #ffffff; border-radius: 16px; padding: 1.5rem 1.8rem;
        margin-bottom: 1.2rem; box-shadow: 0 8px 20px #102a4326;
    }
    .hero h1 { margin: .25rem 0; color: #ffffff; }
    .hero p { color: #e2edf5; margin-bottom: 0; }
    .notice {
        background: #fff7e6; border: 1px solid #e4b64d; border-left: 4px solid #b45309;
        padding: .8rem 1rem; border-radius: 6px; color: #563d00; margin: .8rem 0 1.2rem;
    }
    .notice strong { color: #422d00; }
    div[data-testid="stMetric"] {
        background: var(--surface); border: 1px solid var(--line); border-top: 3px solid var(--accent);
        padding: 1rem; border-radius: 12px; box-shadow: 0 2px 6px #102a430d;
    }
    [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] p {
        color: var(--muted-ink) !important; font-weight: 600;
    }
    [data-testid="stMetricValue"], [data-testid="stMetricValue"] div {
        color: #102a43 !important; font-weight: 700;
    }
    [data-testid="stForm"] {
        background: var(--surface); border: 1px solid var(--line);
        border-radius: 12px; padding: 1rem 1.1rem;
    }
    [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea {
        color: var(--ink) !important; background: #ffffff !important;
        border: 1px solid #94a3b8 !important; border-radius: 7px;
    }
    [data-testid="stTextInput"] input::placeholder,
    [data-testid="stTextArea"] textarea::placeholder { color: #596b80 !important; opacity: 1; }
    [data-testid="stTextInput"] input:focus, [data-testid="stTextArea"] textarea:focus {
        border-color: #0369a1 !important; box-shadow: 0 0 0 2px #0ea5e933 !important;
    }
    [data-testid="stFormSubmitButton"] button {
        background: #075985; border: 1px solid #075985; color: #ffffff;
        font-weight: 700; border-radius: 7px;
    }
    [data-testid="stFormSubmitButton"] button:hover {
        background: #0c4a6e; border-color: #0c4a6e; color: #ffffff;
    }
    [data-testid="stFormSubmitButton"] button:focus-visible {
        outline: 3px solid #38bdf8; outline-offset: 2px;
    }
    [data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 10px; }
    [data-testid="stDataFrame"] * { color: var(--ink); }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">LS CYBERSHIELD · SOC TRAINING CONSOLE</div>
      <h1>Email Threat Triage</h1>
      <p>Offline, explainable rule-based analysis for synthetic email investigations.</p>
    </div>
    <div class="notice"><strong>Training/demo system — not a production security product.</strong>
    Use synthetic content only. No mailbox connections are made and URLs are inspected as text
    only; links are never opened and attachments are never executed.</div>
    """,
    unsafe_allow_html=True,
)

counts, investigations = get_dashboard_data()
metric_columns = st.columns(4)
for column, label, value in zip(
    metric_columns,
    ("Emails analyzed", "Phishing detections", "Suspicious emails", "Clean emails"),
    (counts["total"], counts["Phishing"], counts["Suspicious"], counts["Clean"]),
):
    column.metric(label, value)

left, right = st.columns([1.25, 1], gap="large")
with left:
    st.subheader("Synthetic email investigations")
    st.caption("Every record shown is synthetic training/demo data.")
    table_rows = [
        {
            "Analyzed (UTC)": item["analyzed_at"].replace("T", " ")[:19],
            "Sender": item["sender"],
            "Subject": item["subject"],
            "Verdict": item["verdict"],
            "Risk": f'{item["score"]}/100',
        }
        for item in investigations
    ]
    st.dataframe(table_rows, use_container_width=True, hide_index=True)

with right:
    st.subheader("Analyze a synthetic email")
    with st.form("email_analysis", clear_on_submit=False):
        sender = st.text_input("Sender address", placeholder="alerts@training.example")
        subject = st.text_input("Subject", placeholder="Synthetic training example")
        body = st.text_area("Message body", height=150, placeholder="Paste synthetic text only.")
        submitted = st.form_submit_button("Analyze email", type="primary", use_container_width=True)

    if submitted:
        if not sender.strip() or not subject.strip() or not body.strip():
            st.error("Enter a synthetic sender address, subject, and message body.")
        else:
            result = analyze_email(sender, subject, body)
            save_investigation(sender, subject, result)
            st.session_state["latest_result"] = result

    result = st.session_state.get("latest_result")
    if result:
        st.markdown(f"**{result['verdict']} · Risk score {result['score']}/100**")
        st.progress(result["score"] / 100)
        st.markdown("**Rule findings**")
        for reason in result["reasons"]:
            st.markdown(f"- {reason}")
        st.caption("A clean result means no configured rule matched; it is not a safety guarantee.")

st.divider()
st.caption("LS CyberShield · Local demo data is stored in `cybershield.sqlite3` on this device.")
