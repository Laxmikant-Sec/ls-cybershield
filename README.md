# LS CyberShield

LS CyberShield is a **training/demo system, not a production security product**. This first milestone is a local SOC-style email triage dashboard built with Python, Streamlit, and SQLite.

## What it does

- Shows total analyzed, phishing, suspicious, and clean email counts.
- Seeds a local investigation table with clearly labeled synthetic `.example` messages.
- Analyzes sender address, subject, and body with transparent rules for social-engineering language, lookalike sender domains, and risky URL patterns.
- Returns a 0–100 risk score and a reason for each matched rule.
- Stores investigation results locally in `cybershield.sqlite3` beside `app.py`.

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

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Local data

The database contains synthetic seed messages and any analyses submitted through the demo form. Delete `cybershield.sqlite3` while the app is stopped to reset the local dashboard; it will be recreated with the synthetic seed data on next launch.
