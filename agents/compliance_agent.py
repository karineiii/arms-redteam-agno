def run_compliance(recon_output, attack_output, ai_output):
    return {
        "regulatory_gaps": [
            {
                "framework": "DORA",
                "gap": "Critical third-party dependency insufficiently controlled"
            },
            {
                "framework": "AI Act",
                "gap": "Insufficient traceability and explainability of AI decisions"
            },
            {
                "framework": "MiCA",
                "gap": "Weak security controls around crypto-related operations"
            },
            {
                "framework": "GDPR",
                "gap": "Potential lack of governance over personal data in logs and model pipelines"
            }
        ],
        "affected_controls": [
            "Third-party risk management",
            "Auditability",
            "Logging and traceability",
            "Model monitoring"
        ],
        "missing_evidence": [
            "Resilience test results",
            "Data lineage records",
            "Model monitoring dashboard",
            "Third-party audit evidence"
        ],
        "severity": "high",
        "impacted_regulations": ["DORA", "MiCA", "AI Act", "GDPR"],
        "justification": "The identified cyber and AI attack paths show insufficient resilience, monitoring, and evidence of control effectiveness.",
        "remediation_actions": [
            "Strengthen API validation and integrity checks",
            "Implement data lineage and poisoning detection",
            "Increase audit logging coverage",
            "Test third-party resilience and reversibility"
        ]
    }
