import os
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq
from typer import prompt

from analyzer.parser import parse_input
from analyzer.detector import detect
from analyzer.log_analyzer import analyze_log
from analyzer.risk_engine import calculate_risk
from analyzer.policy_engine import apply_policy

def load_project_env() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return

    for encoding in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            if load_dotenv(dotenv_path=env_path, encoding=encoding):
                return
        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError(
        "dotenv",
        b"",
        0,
        1,
        ".env must be encoded as UTF-8, UTF-8 with BOM, or UTF-16",
    )


# Load environment variables from .env file
load_project_env()

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="Detects sensitive data, analyzes logs and generates AI insights",
    version="1.0.0"
)

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Initialize Anthropic client
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ─── Request/Response Models ───────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    input_type: str  # text | log | sql | chat
    content: str
    options: dict = {
        "mask": True,
        "block_high_risk": True,
        "log_analysis": True
    }


# ─── Health Check ──────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "running", "message": "AI Secure Data Intelligence Platform"}


# ─── Main Analysis Endpoint ────────────────────────────────────────────────────
#parse → detect → risk → policy → AI insights → return
@app.post("/analyze")
async def analyze(request: AnalyzeRequest):

    # Step 1: Parse the input based on type
    cleaned_content = parse_input(request.input_type, request.content)
    # Validation
    if not cleaned_content or len(cleaned_content.strip()) < 3:
        raise HTTPException(
            status_code=400,
            detail="Input content is too short or empty"
        )

    valid_types = ["text", "log", "sql", "chat"]
    if request.input_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid input_type. Must be one of: {valid_types}"
        )
    # Step 2: Run log analyzer or basic detector
    anomalies = []
    if request.input_type == "log":
        log_result = analyze_log(cleaned_content)
        findings = log_result["findings"]
        anomalies = log_result["anomalies"]
        risk_counts = log_result["risk_counts"]
        total_lines = log_result["total_lines"]
    else:
        findings = detect(cleaned_content)
        risk_counts = {}
        total_lines = len(cleaned_content.splitlines())

    # Step 3: Calculate risk score
    risk_result = calculate_risk(findings, anomalies)

    # Step 4: Apply policy (mask or block)
    policy_result = apply_policy(
        findings,
        risk_result["risk_level"],
        request.options
    )

    # Step 5: Get AI insights from Claude
    insights = get_ai_insights(findings, anomalies, risk_result)

    logger.info(f"Analysis complete | type={request.input_type} | risk={risk_result['risk_level']} | score={risk_result['score']} | findings={len(findings)}")

    # Step 6: Build and return final response
    return {
        "summary": insights["summary"],
        "content_type": request.input_type,
        "findings": policy_result["findings"],
        "anomalies": anomalies,
        "risk_score": risk_result["score"],
        "risk_level": risk_result["risk_level"],
        "risk_counts": risk_counts,
        "breakdown": risk_result["breakdown"],
        "action": policy_result["action"],
        "reason": policy_result["reason"],
        "insights": insights["points"],
        "total_lines": total_lines
    }


# ─── File Upload Endpoint ──────────────────────────────────────────────────────

@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    # Read file content
    content = await file.read()

    # Decode bytes to string
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File must be a valid text file (UTF-8 encoded)"
        )

    # Determine input type from file extension
    filename = file.filename.lower()
    if filename.endswith(".pdf"):
        try:
            import PyPDF2
            import io
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            text = "\n".join(
                page.extract_text() or "" 
                for page in reader.pages
            )
            input_type = "text"
        except Exception:
            raise HTTPException(status_code=400, detail="Could not read PDF file")

    # DOC/DOCX support
    elif filename.endswith(".docx"):
        try:
            import docx
            import io
            doc = docx.Document(io.BytesIO(content))
            text = "\n".join(para.text for para in doc.paragraphs)
            input_type = "text"
        except Exception:
            raise HTTPException(status_code=400, detail="Could not read DOCX file")

    
    elif filename.endswith(".log"):
        input_type = "log"
    elif filename.endswith(".sql"):
        input_type = "sql"
    else:
        input_type = "text"

    # Reuse the same analyze logic
    request = AnalyzeRequest(
        input_type=input_type,
        content=text
    )
    return await analyze(request)


# ─── AI Insights Function ──────────────────────────────────────────────────────

def get_ai_insights(findings: list, anomalies: list, risk_result: dict) -> dict:

    if not findings and not anomalies:
        return {
            "summary": "No sensitive data or security issues detected.",
            "points": []
        }

    findings_text = "\n".join([
        f"- {f['type']} (risk: {f['risk']}) on line {f['line']}"
        for f in findings
    ])
    anomalies_text = "\n".join([
        f"- {a['type']}: {a['description']}"
        for a in anomalies
    ]) if anomalies else "None"

    prompt = f"""You are a security analyst reviewing a log/data scan report.

Findings:
{findings_text}

Anomalies:
{anomalies_text}

Risk Score: {risk_result['score']}
Risk Level: {risk_result['risk_level']}

Provide:
1. A one sentence summary of the overall security situation
2. A list of 3 to 5 specific, actionable security insights

Focus especially on:
- Whether API keys or tokens are exposed in logs
- Whether there are multiple failed login attempts
- Whether sensitive user data is logged in plain text
- What immediate actions should be taken

Format your response exactly like this:
SUMMARY: <one sentence>
INSIGHTS:
- <insight 1>
- <insight 2>
- <insight 3>"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.choices[0].message.content
        lines = text.strip().splitlines()

        summary = ""
        points = []

        for line in lines:
            if line.startswith("SUMMARY:"):
                summary = line.replace("SUMMARY:", "").strip()
            elif line.strip().startswith("-"):
                points.append(line.strip().lstrip("- ").strip())

        return {"summary": summary, "points": points}

    except Exception as e:
        print(f"GROQ ERROR: {e}") 
        return {
            "summary": f"Scan complete. Risk level: {risk_result['risk_level']}",
            "points": [f"Found {len(findings)} sensitive items requiring attention"]
        }
    