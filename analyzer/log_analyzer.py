from analyzer.detector import detect


def analyze_log(content: str) -> dict:
    """
    Accepts raw log content as a string.
    Returns structured findings + metadata.
    """

    # Step 1: Run the detection engine on the full log
    findings = detect(content)

    # Step 2: Count findings by risk level
    risk_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    for finding in findings:
        risk = finding["risk"]
        if risk in risk_counts:
            risk_counts[risk] += 1

    # Step 3: Check for brute force pattern
    lines = content.splitlines()
    failed_attempts = sum(
        1 for line in lines
        if any(word in line.lower() for word in ["failed", "unauthorized", "invalid", "denied"])
    )
    brute_force_detected = failed_attempts > 5

    # Step 4: Check for debug mode leak
    debug_detected = any(
        "debug" in line.lower() for line in lines
    )

    # Step 5: Build anomalies list
    anomalies = []

    if brute_force_detected:
        anomalies.append({
            "type": "brute_force",
            "description": f"Multiple failed login attempts detected ({failed_attempts} occurrences)",
            "risk": "high"
        })

    if debug_detected:
        anomalies.append({
            "type": "debug_leak",
            "description": "Debug mode appears to be enabled — internal info may be exposed",
            "risk": "medium"
        })

    # Step 6: SQL injection check
    sql_keywords = ["select ", "drop ", "insert ", "union ", "' or '", "1=1"]
    sql_detected = any(
        any(kw in line.lower() for kw in sql_keywords)
        for line in lines
    )
    if sql_detected:
        anomalies.append({
            "type": "sql_injection_attempt",
            "description": "Possible SQL injection pattern detected in logs",
            "risk": "critical"
        })

    # Step 7: Suspicious scanning — repeated 404s
    not_found_count = sum(
        1 for line in lines
        if "404" in line or "not found" in line.lower()
    )
    if not_found_count > 5:
        anomalies.append({
            "type": "suspicious_scanning",
            "description": f"Repeated 404 errors detected ({not_found_count} times) — possible endpoint scanning",
            "risk": "medium"
        })

    # Step 8: Privilege escalation attempt
    priv_keywords = ["root", "sudo", "admin", "privilege", "escalat"]
    priv_detected = any(
        any(kw in line.lower() for kw in priv_keywords)
        for line in lines
    )
    if priv_detected:
        anomalies.append({
            "type": "privilege_escalation_attempt",
            "description": "Possible privilege escalation attempt detected in logs",
            "risk": "critical"
        })

    # Step 9: Return everything
    return {
        "findings": findings,
        "anomalies": anomalies,
        "risk_counts": risk_counts,
        "total_lines": len(lines),
        "total_findings": len(findings),
    }