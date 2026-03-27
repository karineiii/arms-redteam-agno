def run_risk(recon_output, attack_output, ai_output, compliance_output):
    return {
        "global_risk_score": 0.82,
        "financial_impact": "high",
        "operational_impact": "high",
        "regulatory_impact": "high",
        "reputational_impact": "high",
        "prioritized_findings": [
            {"rank": 1, "finding": "Critical external API dependency not sufficiently controlled"},
            {"rank": 2, "finding": "AI pipeline vulnerable to progressive poisoning"},
            {"rank": 3, "finding": "Insufficient traceability and explainability"},
            {"rank": 4, "finding": "Lack of resilience evidence for critical services"}
        ],
        "executive_summary": "ARMS presents a critical composite risk due to third-party API exposure, weak AI pipeline governance, and significant regulatory compliance gaps."
    }
