import os

import streamlit as st

from detector import analyze_email
from investigation_store import (
    get_dashboard_data,
    initialize_storage,
    is_public_demo,
    save_investigation,
)


st.set_page_config(page_title="LS CyberShield | SOC Email Triage", page_icon="🛡️", layout="wide")


def _public_demo_enabled() -> bool:
    if "CYBERSHIELD_PUBLIC_DEMO" in os.environ:
        return is_public_demo()
    try:
        cloud_setting = st.secrets.get("CYBERSHIELD_PUBLIC_DEMO")
    except FileNotFoundError:
        cloud_setting = None
    return is_public_demo(cloud_secret=str(cloud_setting) if cloud_setting is not None else None)


public_demo = _public_demo_enabled()
initialize_storage(public_demo, st.session_state)

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
    [data-testid="stDataFrame"] [role="gridcell"],
    [data-testid="stDataFrame"] [role="columnheader"] { color: var(--ink); }
    [data-testid="stElementToolbar"] {
        background: #ffffff !important; border: 1px solid #94a3b8 !important;
        border-radius: 8px; box-shadow: 0 2px 8px #102a4326;
    }
    [data-testid="stElementToolbar"] button {
        background: #ffffff !important; color: #172b4d !important;
        border: 1px solid transparent !important; border-radius: 6px;
    }
    [data-testid="stElementToolbar"] button svg {
        color: #172b4d !important;
    }
    [data-testid="stElementToolbar"] button:hover {
        background: #e0f2fe !important; color: #0c4a6e !important;
    }
    [data-testid="stElementToolbar"] button:focus-visible {
        outline: 3px solid #0284c7 !important; outline-offset: 2px;
    }
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

counts, investigations = get_dashboard_data(public_demo, st.session_state)
metric_columns = st.columns(4)
for column, label, value in zip(
    metric_columns,
    ("Emails analyzed", "Phishing detections", "Suspicious emails", "Clean emails"),
    (counts["total"], counts["Phishing"], counts["Suspicious"], counts["Clean"]),
):
    column.metric(label, value)

st.subheader("Analyze a synthetic email")
with st.form("email_analysis", clear_on_submit=False):
    sender_column, subject_column = st.columns(2)
    with sender_column:
        sender = st.text_input("Sender address", placeholder="alerts@training.example")
    with subject_column:
        subject = st.text_input("Subject", placeholder="Synthetic training example")
    body = st.text_area("Message body", height=150, placeholder="Paste synthetic text only.")
    submitted = st.form_submit_button("Analyze email", type="primary", use_container_width=True)

if submitted:
    if not sender.strip() or not subject.strip() or not body.strip():
        st.error("Enter a synthetic sender address, subject, and message body.")
    else:
        result = analyze_email(sender, subject, body)
        save_investigation(
            public_demo,
            st.session_state,
            sender,
            subject,
            body,
            result,
        )
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
st.subheader("Synthetic email investigations")
if public_demo:
    st.caption("Fixed synthetic examples and submissions from this session only.")
else:
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
st.dataframe(
    table_rows,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Analyzed (UTC)": st.column_config.TextColumn(width="medium"),
        "Sender": st.column_config.TextColumn(width="large"),
        "Subject": st.column_config.TextColumn(width="large"),
        "Verdict": st.column_config.TextColumn(width="small"),
        "Risk": st.column_config.TextColumn(width="small"),
    },
)

st.divider()
if public_demo:
    st.caption("Public demo mode · Submissions stay in this Streamlit session and are not saved.")
else:
    st.caption("LS CyberShield · Local demo data is stored in `cybershield.sqlite3` on this device.")
