# Risk weights — how many points each risk level adds to the total score
RISK_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1
}

# Score bands — total score maps to a risk level
RISK_BANDS = [
    (15, "critical"),
    (8,  "high"),
    (4,  "medium"),
    (0,  "low")
]


def calculate_risk(findings: list, anomalies: list) -> dict:
    """
    Takes findings and anomalies, returns a risk score and level.
    """

    # Step 1: Add up scores from all findings
    score = 0
    for finding in findings:
        risk = finding.get("risk", "low")
        score += RISK_WEIGHTS.get(risk, 0)

    # Step 2: Add up scores from anomalies too
    for anomaly in anomalies:
        risk = anomaly.get("risk", "low")
        score += RISK_WEIGHTS.get(risk, 0)

    # Step 3: Map total score to a risk level
    # Go through bands top to bottom, first one that fits wins
    risk_level = "low"
    for threshold, level in RISK_BANDS:
        if score >= threshold:
            risk_level = level
            break

    # Step 4: Return score + level + a breakdown by type
    breakdown = {}
    for finding in findings:
        ftype = finding.get("type", "unknown")
        if ftype not in breakdown:
            breakdown[ftype] = 0
        breakdown[ftype] += 1

    return {
        "score": score,
        "risk_level": risk_level,
        "breakdown": breakdown
    }

