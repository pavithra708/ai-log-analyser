# AI Secure Data Intelligence Platform

A modular AI-powered system for detecting sensitive data, analyzing logs, and identifying security risks across multiple input sources.

---

## 🌐 Live Demo

🔗 https://ai-secure-platform-l42o.onrender.com/

The application is publicly deployed and allows real-time analysis of logs, SQL queries, files, and text inputs.

> ⚠️ Note: The app may take a few seconds to load due to cold start on free hosting.

---

## 🚨 Problem Statement

Modern applications generate large volumes of logs that often contain sensitive information such as passwords, API keys, and system errors. If not monitored, these can lead to serious security vulnerabilities and data leaks.

---

## 💡 Solution

This project provides a unified platform to analyze logs and multiple data sources, detect sensitive information, classify risks, and generate actionable AI-driven security insights.

---

## 🎯 Key Features

* Multi-input support: `text`, `log`, `sql`, `chat`
* File uploads: `.log`, `.txt`, `.sql`, `.pdf`, `.docx`
* Sensitive data detection:

  * Credentials: password, token, api_key, jwt, aws keys
  * PII: email, phone, credit card
  * Security leaks: stack traces, DB URLs, IPs
* Log anomaly detection:

  * Brute-force attempts
  * Suspicious IP activity
  * SQL injection patterns
  * Debug leaks
* Risk scoring and classification
* Policy engine (mask / block / allow)
* AI-generated insights and summaries
* Interactive UI with:

  * Risk indicators
  * Findings table
  * Highlighted log visualization

---

## 🏗️ System Architecture

```
Input (Text / Log / SQL / File / Chat)
        ↓
Parser & Extraction Layer
        ↓
Detection Engine (Regex + AI + Log Analyzer)
        ↓
Risk Engine (Scoring + Classification)
        ↓
Policy Engine (Mask / Block / Pass)
        ↓
AI Insights Generator
        ↓
Frontend Visualization
```

---

## 📤 Sample Output

```json
{
  "summary": "Sensitive credentials and errors detected in logs",
  "risk_score": 14,
  "risk_level": "high",
  "action": "blocked",
  "findings": [
    {"type": "email", "risk": "low"},
    {"type": "password", "risk": "critical"},
    {"type": "stack_trace", "risk": "medium"}
  ],
  "insights": [
    "Sensitive credentials exposed",
    "Stack trace reveals internal system details"
  ]
}
```

---

## 🎯 Key Focus

This project focuses primarily on log analysis, a critical component for identifying security risks in real-world systems, while also supporting multi-source data ingestion.

---

## 🚀 Highlights

* Modular and scalable architecture
* Real-time risk scoring
* AI-powered insights
* Advanced log visualization with severity highlighting

---

## 📁 Project Structure

```
ai-log-secure/
  analyzer/
    detector.py
    log_analyzer.py
    parser.py
    policy_engine.py
    risk_engine.py
  frontend-react/
    src/
    dist/
  main.py
  requirements.txt
```

---

## ⚙️ Setup Instructions

### 1. Clone repository

```bash
git clone <your-repo-url>
cd ai-log-secure
```

---

### 2. Create virtual environment

```bash
python -m venv .venv
```

Activate:

**Windows**

```bash
.\.venv\Scripts\activate
```

**Mac/Linux**

```bash
source .venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Configure environment

Create `.env`:

```env
GROQ_API_KEY=your_api_key_here
```

---

### 5. Install frontend

```bash
cd frontend-react
npm install
npm run build
cd ..
```

---

### 6. Run backend

```bash
python -m uvicorn main:app --reload
```

---

## 🌍 Access URLs

* UI: http://127.0.0.1:8000/
* API Docs: http://127.0.0.1:8000/docs
* Health: http://127.0.0.1:8000/health

---

## 🔌 API

### POST `/analyze`

```json
{
  "input_type": "log",
  "content": "your input here",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```

---

## 📌 Demo Input

```log
2026-03-10 INFO User login
email=admin@company.com
password=admin123
api_key=sk-prod-xyz
ERROR stack trace: NullPointerException
```

---

## 🚀 Deployment

Deployed on Render for real-time access and testing.

---

## 🧠 Tech Stack

* Backend: FastAPI (Python)
* Frontend: React
* AI: Groq API
* Deployment: Render


