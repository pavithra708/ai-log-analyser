import os
from collections import Counter
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq

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
FRONTEND_DIST_DIR = Path("frontend-react") / "dist"

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

@app.get("/health")
def health():
    return {"status": "running", "message": "AI Secure Data Intelligence Platform"}


@app.get("/")
def root():
    index_file = FRONTEND_DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse(
        status_code=503,
        content={
            "status": "frontend_not_built",
            "message": "React frontend build not found. Run: cd frontend-react && npm run build"
        },
    )


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


@app.get("/{full_path:path}")
async def frontend_routes(full_path: str):
    if full_path.startswith(("analyze", "docs", "redoc", "openapi.json", "health")):
        raise HTTPException(status_code=404, detail="Not found")

    asset_path = FRONTEND_DIST_DIR / full_path
    if asset_path.exists() and asset_path.is_file():
        return FileResponse(asset_path)

    index_file = FRONTEND_DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)

    raise HTTPException(
        status_code=503,
        detail="Frontend build not found. Run: cd frontend-react && npm run build"
    )


# ─── AI Insights Function ──────────────────────────────────────────────────────

def get_ai_insights(findings: list, anomalies: list, risk_result: dict) -> dict:

    if not findings and not anomalies:
        return {
            "summary": "No sensitive data or security issues detected.",
            "points": []
        }

    type_counts = Counter(f["type"] for f in findings)
    finding_risk_counts = Counter(f["risk"] for f in findings)
    anomaly_risk_counts = Counter(a["risk"] for a in anomalies)
    combined_risk_counts = finding_risk_counts + anomaly_risk_counts
    anomaly_types = [a["type"] for a in anomalies]
    top_type = type_counts.most_common(1)[0][0] if type_counts else "none"

    evidence_lines = []
    for finding_type, count in type_counts.most_common():
        evidence_lines.append(f"- finding_type={finding_type}, count={count}")
    for risk, count in combined_risk_counts.most_common():
        evidence_lines.append(f"- risk_level={risk}, count={count}")
    for anomaly in anomalies:
        evidence_lines.append(f"- anomaly={anomaly['type']}, risk={anomaly['risk']}")

    evidence_text = "\n".join(evidence_lines) if evidence_lines else "- none"

    fallback_summary = (
        f"Scan detected {len(findings)} findings and {len(anomalies)} anomalies; "
        f"overall risk is {risk_result['risk_level']} (score {risk_result['score']})."
    )

    fallback_points = []
    if type_counts.get("password", 0) > 0 or type_counts.get("secret", 0) > 0:
        fallback_points.append(
            f"Credentials exposure detected ({type_counts.get('password', 0)} password entries, "
            f"{type_counts.get('secret', 0)} secret entries). Rotate affected secrets immediately."
        )
    if type_counts.get("api_key", 0) > 0 or type_counts.get("token", 0) > 0 or type_counts.get("jwt_token", 0) > 0:
        fallback_points.append(
            f"Token/API material found in logs ({type_counts.get('api_key', 0)} api_key, "
            f"{type_counts.get('token', 0)} token, {type_counts.get('jwt_token', 0)} jwt_token). "
            "Revoke and reissue exposed keys."
        )
    if "brute_force" in anomaly_types:
        fallback_points.append(
            "Brute-force behavior detected from repeated authentication failures. "
            "Enable account lockout and IP-based rate limiting."
        )
    if "suspicious_ip_activity" in anomaly_types:
        fallback_points.append(
            "Suspicious repeated requests from one or more IPs were detected. "
            "Block offending IPs and review access logs for abuse windows."
        )
    if "sql_injection_attempt" in anomaly_types:
        fallback_points.append(
            "SQL injection-like patterns were observed in log traffic. "
            "Validate input handling and enforce parameterized queries."
        )
    if "debug_leak" in anomaly_types or type_counts.get("stack_trace", 0) > 0:
        fallback_points.append(
            "Debug traces/internal errors appear in output. Disable debug mode in production and sanitize error responses."
        )
    if type_counts.get("email", 0) > 0 or type_counts.get("phone", 0) > 0 or type_counts.get("credit_card", 0) > 0:
        fallback_points.append(
            f"Sensitive user data appears in logs (email={type_counts.get('email', 0)}, "
            f"phone={type_counts.get('phone', 0)}, credit_card={type_counts.get('credit_card', 0)}). "
            "Apply data minimization and masking at log write time."
        )
    if not fallback_points:
        fallback_points.append(
            f"Primary exposure category is '{top_type}'. Prioritize controls for this category before lower-risk items."
        )

    # Keep a stable 3 to 5 items for UI consistency and hackathon scoring expectations.
    fallback_points = fallback_points[:5]
    if len(fallback_points) < 3:
        fallback_points.append(
            f"Risk distribution: critical={combined_risk_counts.get('critical', 0)}, "
            f"high={combined_risk_counts.get('high', 0)}, "
            f"medium={combined_risk_counts.get('medium', 0)}, "
            f"low={combined_risk_counts.get('low', 0)}."
        )
    fallback_points = fallback_points[:5]

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

Evidence Summary:
{evidence_text}

Risk Score: {risk_result['score']}
Risk Level: {risk_result['risk_level']}

Provide:
1. A one sentence summary of the overall security situation
2. A list of 3 to 5 specific, actionable security insights

Rules:
- Use only the provided evidence. Do not invent events.
- Every insight must cite concrete evidence (counts, finding type, anomaly type, or risk level).
- Prioritize immediate actions based on highest risk items.
- Avoid generic statements like "security risk detected" without details.

Format your response exactly like this:
SUMMARY: <one sentence>
INSIGHTS:
- <insight 1>
- <insight 2>
- <insight 3>"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            temperature=0.2,
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

        generic_markers = [
            "security risk",
            "immediate action should be taken",
            "sensitive data was found",
            "potential issue",
            "review and monitor",
        ]

        def is_generic(message: str) -> bool:
            lowered = message.lower()
            has_evidence = any(token in lowered for token in list(type_counts.keys()) + anomaly_types)
            has_number = any(char.isdigit() for char in lowered)
            return (not has_evidence and not has_number) or any(marker in lowered for marker in generic_markers)

        cleaned_points = []
        for point in points:
            if len(cleaned_points) >= 5:
                break
            if point and point not in cleaned_points and not is_generic(point):
                cleaned_points.append(point)

        for fallback in fallback_points:
            if len(cleaned_points) >= 5:
                break
            if fallback not in cleaned_points:
                cleaned_points.append(fallback)

        final_summary = summary if summary else fallback_summary
        final_points = cleaned_points[:5]
        if len(final_points) < 3:
            final_points = fallback_points[:3]

        return {"summary": final_summary, "points": final_points}

    except Exception as e:
        print(f"GROQ ERROR: {e}")
        return {
            "summary": fallback_summary,
            "points": fallback_points[:3]
        }
    
