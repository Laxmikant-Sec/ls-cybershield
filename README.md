# LS CyberShield

LS CyberShield is a **training/demo system, not a production security product**. It is a SOC-style email triage dashboard built with Python and Streamlit. Local development uses SQLite; public demo deployments can use per-session ephemeral state.

## What it does

- Shows total analyzed, phishing, suspicious, and clean email counts.
- Seeds a local investigation table with clearly labeled synthetic `.example` messages.
- Analyzes sender address, subject, and body with transparent rules for social-engineering language, lookalike sender domains, and risky URL patterns.
- Returns a 0–100 risk score and a reason for each matched rule.
- Stores local-development investigation results in `cybershield.sqlite3` beside `app.py`.
- Supports an explicitly enabled public demo mode that uses fixed synthetic seeds and keeps each visitor's submissions only in that visitor's Streamlit session.

The detector only parses URL text. It does not visit links, connect to mailboxes, retrieve messages, execute attachments, or ask for/store credentials. **Submit synthetic examples only.** Use of real email content is outside this demo's intended scope.

## Windows ARM64 setup

Use a native Windows ARM64 installation of Python 3.11 or newer. In PowerShell, open the repository folder and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks activation, use the environment's interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL printed by Streamlit, typically `http://localhost:8501`. No cloud service or mailbox credentials are required. Streamlit/Python ARM64 wheel availability depends on the selected Python release; if installation reports an unsupported wheel, use a current native ARM64 Python release supported by Streamlit and repeat the setup in a fresh virtual environment.

## Streamlit Community Cloud deployment

Deploy this repository through Streamlit Community Cloud with `app.py` as the app entry point. **Enable public demo mode explicitly** so visitors never share SQLite-backed submissions:

- In Community Cloud, open the app's **Settings → Secrets** and add the TOML setting:

  ```toml
  CYBERSHIELD_PUBLIC_DEMO = "1"
  ```

- For other deployment environments, set the process environment variable `CYBERSHIELD_PUBLIC_DEMO=1`.

The app also reads the Streamlit secret when the environment variable is unset. The exact value `"1"` enables public mode; any other explicitly set environment value keeps local mode enabled. Public mode does not initialize, read, or write SQLite. Each Streamlit session gets the same fixed synthetic seed examples, then sees only its own submitted synthetic messages and analysis results. Session data is not durable and may disappear when the session ends or the app restarts. Do not configure production email access, credentials, or persistent shared storage.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Local data

In local mode, the database contains synthetic seed messages and analyses submitted through the demo form. Delete `cybershield.sqlite3` while the app is stopped to reset the local dashboard; it will be recreated with synthetic seed data on next launch. Public demo mode does not use this database.
