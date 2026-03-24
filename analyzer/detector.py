#regex detection engine
import re

#Each pattern here has type,pattern,risk and description
PATTERNS = [
    {
        "type": "email",
        "pattern": r"[\w.+-]+@[\w-]+\.[a-z]{2,}",
        "risk": "low",
        "description": "Email address found"
    },
    {
        "type": "phone",
        "pattern": r"\b(\+91|0)?[6-9]\d{9}\b",
        "risk": "low",
        "description": "Phone number found"
    },
    {
        "type": "api_key",
        "pattern": r"(sk|api|key|token)[-_]?[a-zA-Z0-9]{16,}",
        "risk": "high",
        "description": "API key or token found"
    },
    {
        "type": "password",
        "pattern": r"password\s*[:=]\s*\S+",
        "risk": "critical",
        "description": "Hardcoded password found"
    },
    {
        "type": "secret",
        "pattern": r"secret\s*[:=]\s*\S+",
        "risk": "critical",
        "description": "Secret value found"
    },
    {
        "type": "jwt_token",
        "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "risk": "high",
        "description": "JWT token found"
    },
    {
        "type": "ip_address",
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "risk": "medium",
        "description": "IP address found"
    },
    {
        "type": "stack_trace",
        "pattern": r"(Exception|Error|Traceback|NullPointer|StackOverflow).{0,60}",
        "risk": "medium",
        "description": "Stack trace or error leak found"
    },
    {
        "type": "credit_card",
        "pattern": r"\b(?:\d[ -]?){13,16}\b",
        "risk": "critical",
        "description": "Possible credit card number found"
    },
    {
    "type": "aws_key",
    "pattern": r"AKIA[0-9A-Z]{16}",
    "risk": "critical",
    "description": "AWS access key found"
    },
    {
    "type": "database_url",
    "pattern": r"(mysql|postgresql|postgres|sqlite)://[^\s]+",
    "risk": "critical",
    "description": "Database connection URL found"
   },
]

def detect(text: str) -> list:
    """
    Runs all patterns against the input text.
    Returns a list of findings.
    """
    findings = []
    lines = text.splitlines()

    for line_num, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            matches = re.findall(pattern["pattern"], line, re.IGNORECASE)
            for match in matches:
                # match can be a tuple if pattern has groups, take first element
                value = match if isinstance(match, str) else match[0]
                findings.append({
                    "type": pattern["type"],
                    "value": value,
                    "risk": pattern["risk"],
                    "description": pattern["description"],
                    "line": line_num
                })

    return findings
