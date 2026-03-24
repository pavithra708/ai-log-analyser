# What action to take based on risk level and options
def apply_policy(findings: list, risk_level: str, options: dict) -> dict:
    """
    Takes findings, risk level and user options.
    Returns masked findings and the action taken.
    """

    mask = options.get("mask", True)
    block_high_risk = options.get("block_high_risk", True)

    # Step 1: Check if we should block the request entirely
    if block_high_risk and risk_level in ["critical", "high"]:
        return {
            "action": "blocked",
            "reason": f"Request blocked due to {risk_level} risk level",
            "findings": findings
        }

    # Step 2: Mask sensitive values if masking is enabled
    masked_findings = []
    for finding in findings:
        masked = finding.copy()
        if mask and finding["risk"] in ["critical", "high", "medium"]:
            masked["value"] = f"[{finding['type'].upper()} REDACTED]"
        masked_findings.append(masked)

    # Step 3: Determine action label
    if mask:
        action = "masked"
    else:
        action = "passed"

    return {
        "action": action,
        "reason": None,
        "findings": masked_findings
    }