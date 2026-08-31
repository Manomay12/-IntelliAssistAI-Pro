# 🛡️ INTELASSIST AI
### AI-Powered Cyber Threat Intelligence & Investigation Platform

> *"Transforming Threat Data into Actionable Intelligence"*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-38bdf8.svg?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-ef4444.svg?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Vector Engine](https://img.shields.io/badge/Vector_DB-Dense_384--dim-10b981.svg)](https://github.com)
[![SOC Platform](https://img.shields.io/badge/SOC_Platform-Cyber_Threat_Intel-a855f7.svg)](https://github.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b.svg)](LICENSE)

---

## 📌 Overview & Executive Summary

**IntelAssist AI** is a production-grade, hackathon-ready **Cyber Threat Intelligence (CTI) & Incident Investigation Platform**. It empowers cybersecurity analysts, incident responders, and SOC teams to ingest unstructured threat reports, security logs, vulnerability disclosures, and indicators of compromise (IOCs), correlating multi-artifact evidence into explainable risk assessments and structured attack timelines.

Unlike traditional generic chat tools, IntelAssist AI features **evidence-grounded retrieval-augmented generation (RAG)** that strictly separates **Observed Evidence** from **Analyst Hypotheses**, maps techniques to the **MITRE ATT&CK Framework**, and provides complete offline functionality with zero external API dependencies required.

---

## 🏛️ System Architecture

```
========================================================================================================
                                     INTELASSIST AI SOC PLATFORM
========================================================================================================

    [ THREAT ARTIFACT INGESTION ]
    ┌───────────────────────────┐  ┌───────────────────────────┐  ┌───────────────────────────┐
    │  PDF Threat Advisories    │  │  Linux / Auth Logs        │  │  Firewall / Network Logs  │
    │  (APT29, Ransomware, etc) │  │  (sshd, sudo, audit.log)  │  │  (iptables, UFW, Nginx)   │
    └─────────────┬─────────────┘  └─────────────┬─────────────┘  └─────────────┬─────────────┘
                  │                              │                              │
                  ▼                              ▼                              ▼
    ┌─────────────────────────────────────────────────────────────────────────────────────────┐
    │                         MULTI-MODAL EXTRACTION & FORENSIC PIPELINE                      │
    ├─────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
    │  Document Text Chunker      │  Automated IOC Extractor    │  Log Forensic Rule Engine   │
    │  (Sliding-window overlap,   │  (IPs, Domains, SHA256,     │  (Brute force, Port scans,  │
    │   Page & Boundary mapping)  │   CVEs, URLs, Defanging)    │   SQLi, Priv-escalation)    │
    └─────────────┬───────────────┴──────────────┬──────────────┴──────────────┬──────────────┘
                  │                              │                              │
                  ▼                              ▼                              ▼
    ┌─────────────────────────────┐┌────────────────────────────┐┌────────────────────────────┐
    │    Dense 384-dim Embeddings ││   Threat Correlator        ││   MITRE ATT&CK Mapper      │
    │    & Vector Database        ││   (Cross-source discovery) ││   (T1110, T1078, T1071...) │
    └─────────────┬───────────────┘└─────────────┬──────────────┘└─────────────┬──────────────┘
                  │                              │                             │
                  ▼                              ▼                             ▼
    ┌─────────────────────────────────────────────────────────────────────────────────────────┐
    │                           EXPLAINABLE RISK & CORRELATION ENGINE                         │
    │    • 0-100 Quantitative Risk Score • Itemized Factor Breakdown • Plotly Network Graph   │
    └────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                 │
                                                 ▼
    ┌─────────────────────────────────────────────────────────────────────────────────────────┐
    │                         CYBER RAG & LLM SYNTHESIS CONTROLLER                            │
    │   Providers: Google Gemini Flash/Pro • NVIDIA NIM • OpenAI GPT-4o • Smart Local Cyber NLP│
    └────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                 │
                                                 ▼
    ┌─────────────────────────────────────────────────────────────────────────────────────────┐
    │                         STREAMLIT SOC OPERATIONS INTERFACE (UI/UX)                      │
    ├───────────────────┬───────────────────┬───────────────────┬─────────────────────────────┤
    │ 📊 SOC Dashboard  │ 🎯 IOC Correlator │ 📋 Log Analyzer   │ 🤖 AI Incident Assistant    │
    │ ⏱️ Attack Timeline│ 🏷️ IOC Explorer   │ 💬 Intel Chat     │ 📝 Threat Briefing Summaries│
    └───────────────────┴───────────────────┴───────────────────┴─────────────────────────────┘
========================================================================================================
```

---

## ⚡ Core Features & Capabilities

### 1. 🔍 Cyber Threat Document Intelligence (RAG)
- Ingests **PDF**, **DOCX**, **TXT**, and **Markdown** threat advisories, malware analyses, and incident response reports.
- Computes SHA-256 cryptographic integrity hashes.
- Performs dense 384-dimensional semantic chunking and cosine similarity indexing.
- Supports **Strict Single-Document Scoping** as well as **Cross-Repository Intelligence Synthesis**.

### 2. 🏷️ Automated IOC Extraction Engine (`services/ioc_extractor.py`)
- Regular expression and heuristic parsing for:
  - **IPv4 & IPv6 Addresses** (with RFC 1918 private range classification)
  - **Domains & FQDNs**
  - **URLs & Phishing Links**
  - **Cryptographic Hashes**: SHA256, SHA1, MD5
  - **Vulnerability CVEs** (e.g. `CVE-2023-38831`, `CVE-2021-44228`)
  - **Suspicious Tools & Binaries** (e.g. `mimikatz.exe`, `beacon.dll`, `webshell.php`)
- **Automated Defanging**: Converts `185.220.101.5` ➔ `185[.]220[.]101[.]5` and `http` ➔ `hxxp` to prevent accidental clicks.
- **Context Extraction**: Extracts 80-character surrounding context for explainability.

### 3. 📋 Forensic Log Analysis & Attack Detection (`services/log_analyzer.py`)
- Parses Linux `auth.log`, firewall (iptables/UFW), web server (Apache/Nginx access logs), and CSV security logs.
- Detects:
  - **SSH Brute-Force Attacks** (e.g. >5 failed attempts within 2-minute windows)
  - **Account Compromise** (successful login following brute-force bursts)
  - **Privilege Escalation** (`sudo` abuses and `su root` transitions)
  - **Port Scanning & Reconnaissance** (>10 distinct destination ports probed)
  - **Web Attacks** (SQL Injection `' OR '1'='1`, Directory Traversal `../../etc/passwd`)
- Generates actionable SOC mitigation recommendations.

### 4. 🎯 Threat Correlation & Relationship Graphs (`services/threat_correlator.py`)
- Deep-dives into any single indicator (IP, Domain, Hash, CVE).
- Uncovers cross-artifact links across threat reports and authentication logs.
- Generates **Interactive Plotly 2D Network Graphs** mapping the Target Indicator ➔ Linked Documents ➔ Associated Telemetry Events ➔ Co-occurring Indicators.

### 5. 🧮 Explainable Risk Scoring Engine (`services/risk_engine.py`)
- Computes transparent 0–100 risk scores with itemized factor point breakdowns:
  - *Base Indicator Type Weight* (+10 to +25 pts)
  - *Cross-Source Corroboration* (+8 to +25 pts)
  - *Log Telemetry Volume* (+10 to +25 pts)
  - *High-Severity Context Triggers* (C2, Ransomware, Exploit: +20 pts)
- Categorizes threats into **Critical (81-100)**, **High (61-80)**, **Elevated (41-60)**, **Medium (21-40)**, and **Low (0-20)**.

### 6. 🤖 AI Incident Investigation Assistant (`pages_views/ai_investigation_view.py`)
- Reconstructs end-to-end incident timelines and attack flows.
- Formulates answers in 5 structured forensic sections:
  1. **Executive Incident Assessment & Severity**
  2. **Chronological Incident Timeline**
  3. **Attack Flow & MITRE ATT&CK Chain**
  4. **Evidence Classification** (*Observed Evidence* vs *Corroborated Links* vs *Hypotheses*)
  5. **Recommended SOC Containment & Eradication Steps**
- Exports findings to formatted Markdown.

### 7. ⏱️ Chronological Attack Timeline (`pages_views/timeline_view.py`)
- Sequenced timeline of all observed reconnaissance probes, failed logins, privilege changes, and threat advisory milestones.
- Filterable by Severity, Event Type, and Source File.

### 8. 🛡️ MITRE ATT&CK Technique Mapping (`services/mitre_mapper.py`)
- Correlates evidence to techniques including:
  - `T1110` (Brute Force)
  - `T1078` (Valid Accounts)
  - `T1059` (Command & Scripting Interpreter)
  - `T1548` (Abuse Elevation Control Mechanism)
  - `T1046` (Network Service Scanning)
  - `T1190` (Exploit Public-Facing Application)
  - `T1071` (Application Layer Protocol / C2)
  - `T1003` (OS Credential Dumping)
  - `T1566` (Phishing)
  - `T1486` (Data Encrypted for Impact)

### 9. 🔐 Authentication & User Roles (`services/auth_service.py`)
- Local SQLite database persistence (`data/users/users.db`).
- Salted **PBKDF2 HMAC-SHA256** password hashing with 100,000 iterations.
- 1-Click **Demo Security Analyst** login (`analyst` / `intelassist2026`).

### 10. 🌐 Multi-Provider AI Architecture
- **Google Gemini** (`gemini-1.5-flash`, `gemini-1.5-pro`, `gemini-2.0-flash`)
- **NVIDIA NIM** (`meta/llama-3.1-70b-instruct`, `mistralai/mixtral-8x7b-instruct`)
- **OpenAI** (`gpt-4o`, `gpt-4o-mini`)
- **Smart Local Cyber NLP Engine**: 100% self-contained offline analysis that functions seamlessly without external API keys or credit requirements.

---

## 📁 Repository Structure

```
d:/Intelliassist Ai pro/intelliassist_ai/
├── app.py                         # Main Streamlit SOC Application Controller
├── requirements.txt               # Dependencies (streamlit, pypdf, python-docx, plotly, etc.)
├── README.md                      # Comprehensive Architecture & Documentation
├── test_services.py               # Complete 10-Phase End-to-End Verification Test Suite
├── test_doc_targeting.py          # Document Scoping & Targeting Test Suite
├── data/                          # Persistent Platform Data
│   ├── documents/                 # Ingested Threat Reports & Advisories
│   ├── logs/                      # Ingested Security Logs (auth.log, firewall.log)
│   ├── users/                     # SQLite Auth Database (users.db)
│   └── vector_db/                 # Chunks metadata and vectors index (.npy)
├── services/                      # Core Intelligence Engines
│   ├── auth_service.py            # SQLite Authentication & PBKDF2 Password Hashing
│   ├── chunker.py                 # Document Chunker with Boundary Preservation
│   ├── conversation_manager.py    # Case Discussion Persistence & History
│   ├── document_processor.py      # PDF, DOCX, TXT Text Extraction & Cleaning
│   ├── embeddings.py              # Dense 384-dim Vector Embedding Service
│   ├── ioc_extractor.py           # Automated IOC Extraction, Normalization & Defanging
│   ├── llm_service.py             # Multi-Provider Cyber LLM Client
│   ├── log_analyzer.py            # Heuristic Log Forensic Analyzer
│   ├── mitre_mapper.py            # MITRE ATT&CK Technique Mapper
│   ├── rag_engine.py              # Grounded Cyber RAG Synthesizer
│   ├── risk_engine.py             # Explainable 0-100 Risk Scoring Engine
│   ├── sentiment_analyzer.py      # Severity, Intent & Tone Analyzer
│   ├── summarizer.py              # Threat Briefing & Cross-Report Comparator
│   ├── threat_correlator.py       # Multi-Artifact Correlator & Plotly Graph Builder
│   └── vector_store.py            # Cosine Similarity Vector Database
├── components/                    # UI Components
│   ├── charts.py                  # Plotly Visuals (Risk Gauge, IOC Donut, Timeline Density)
│   ├── chat_ui.py                 # Intel Chat Bubbles & Threat Prompt Chips
│   ├── metrics.py                 # 6 SOC Metric Cards Grid
│   ├── sidebar.py                 # Categorized Dark SOC Navigation & Live Telemetry
│   ├── styles.py                  # Dark SOC Theme CSS (Slate #0b1325, Sky Blue, Glassmorphism)
│   └── source_card.py             # Forensic Source Citation Cards
├── pages_views/                   # SOC Workspaces
│   ├── auth_view.py               # Login & Registration Page
│   ├── dashboard_view.py          # SOC Operations Center Dashboard
│   ├── documents_view.py          # Threat Reports & Artifact Repository
│   ├── investigation_view.py      # Single Indicator Investigation & Correlation
│   ├── ioc_explorer_view.py       # Interactive IOC Table with CSV/JSON Export
│   ├── log_analysis_view.py       # Forensic Log Analysis & Brute-Force Cards
│   ├── ai_investigation_view.py   # AI Incident Investigation Assistant
│   ├── timeline_view.py           # Chronological Attack Timeline
│   ├── chat_view.py               # Cyber Intelligence Q&A Chat
│   ├── summarizer_view.py         # Threat Briefings & Adversary Comparison
│   ├── search_view.py             # Semantic Vector Search
│   ├── analytics_view.py          # SOC Telemetry & Threat Metrics
│   ├── history_view.py            # Case Files & Investigation Records
│   └── settings_view.py           # Platform, API & Model Configuration
├── tests/                         # Unit Test Suite (Unittest / Pytest compatible)
│   ├── test_cyber_services.py     # Cyber Engines Unit Tests
│   ├── test_chunker.py            # Chunker Unit Tests
│   ├── test_document_processor.py # Document Processing Tests
│   ├── test_embeddings.py         # Embedding Dimensions & Norm Tests
│   ├── test_rag.py                # RAG Synthesizer Tests
│   ├── test_sentiment.py          # Sentiment & Intent Tests
│   ├── test_summarizer_and_compare.py # Summarization Tests
│   └── test_vector_store.py       # Vector DB Cosine Index Tests
└── utils/                         # Utilities & Configurations
    ├── config.py                  # App Metadata, Paths, Colors & Model Constants
    ├── helpers.py                 # Risk Badges, Defanging & File Icons
    └── sample_docs.py             # High-Fidelity Cyber Sample Dataset Generator
```

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Virtual environment (`venv` or `conda`)

### 2. Setup Virtual Environment
```bash
cd "d:\Intelliassist Ai pro\intelliassist_ai"
python -m venv .venv

# Activate on Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Activate on Linux / macOS:
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Platform
```bash
streamlit run app.py
```
*The browser will automatically open at `http://localhost:8501`.*

---

## ⚡ Hackathon Evaluator 1-Click Demo Walkthrough

1. **Launch the Application**: Open `http://localhost:8501`.
2. **Instant Demo Analyst Login**: The platform defaults to the **Lead SOC Investigator** account (`analyst`).
3. **Load Demo Investigation**: On the **Dashboard**, click the prominent `⚡ Load Demo Investigation` button.
   - Automatically generates and indexes:
     - 📕 `Sample_Threat_Intel_Report_APT29.pdf` (APT29 WinRAR CVE-2023-38831 spear-phishing campaign)
     - 📘 `Incident_Response_Forensics_Report.docx` (Forensics on Cobalt Strike lateral movement)
     - 📋 `Sample_Auth_BruteForce.log` (51 SSH brute-force events from `185.220.101.5`)
     - 🛡️ `Sample_Firewall_Traffic.log` (Inbound scanning probes)
     - 🌐 `Sample_Web_Server_Attacks.log` (SQL injection attempts)
     - 📊 `Sample_IOC_Feed.csv` (High-confidence IOC blocklist)
4. **Inspect Threat Investigation**: Navigate to **Threat Investigation** and click `185.220.101.5`:
   - Inspect the **80/100 (High Risk)** gauge.
   - Expand the **Explainable Point Factor Breakdown**.
   - Interact with the **Plotly 2D Relationship Graph** connecting the IP to reports and auth logs.
5. **Explore Extracted IOCs**: Navigate to **IOC Explorer** to filter, search, defang, or download indicators as **CSV** or **JSON**.
6. **Analyze Forensic Logs**: Navigate to **Log Analysis** to inspect the detected **SSH Brute-Force & Compromise** alert card and chronological event timeline.
7. **Ask AI Incident Assistant**: Navigate to **AI Investigation Assistant** and click `What happened during this security incident and what is the full attack chain?` to view the structured evidence-grounded incident report.

---

## 🧪 Automated Testing & Verification

Run the comprehensive test suites:

```bash
# 1. Run the complete 10-Phase Cyber Verification Test Suite:
python test_services.py

# 2. Run the Multi-Document Scoping & Strict Targeting Suite:
python test_doc_targeting.py

# 3. Run all unit tests:
python -m unittest discover -s tests
```

*All 36 unit tests pass in under 0.5s.*

---

## 🔑 Optional API Key Configuration

IntelAssist AI is **100% functional out-of-the-box in Demo Mode** using its built-in local NLP engine. If you wish to connect cloud LLMs:

Create a `.env` file in the root directory:
```ini
GEMINI_API_KEY=your_google_gemini_api_key_here
NVIDIA_API_KEY=your_nvidia_nim_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```
Or configure keys directly in the **Settings** page within the application UI.

---

## ⚖️ Ethics & Transparency Disclaimer

IntelAssist AI uses **explainable heuristic detection algorithms** and evidence-grounded semantic retrieval. Detections are derived from clear rule sets (e.g. failed login frequency, port diversity, known indicator matching) and are transparently itemized with point breakdowns. The platform does not make false AI claims and provides analysts with verifiable citations to source artifacts.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
