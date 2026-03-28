from agno.agent import Agent
from agents.common import safe_run


def build_compliance_agent():
    return Agent(
        name="ComplianceBreakerAgent",
        instructions="""
You are the Compliance Breaker Agent.

Mission:
- formally identify regulatory breaches and compliance gaps
- translate technical findings into DORA, MiCA, AI Act and GDPR issues

Return STRICT JSON only.
"""
    )


def run_compliance(recon_output: str, attack_output: str, ai_output: str):
    fallback_output = {
        "identified_gaps": [
            {
                "framework": "DORA",
                "gap": "Critical third-party dependency insufficiently controlled",
                "evidence": "Crypto API connector is a critical dependency with weak transaction integrity assurance",
                "severity": "high"
            },
            {
                "framework": "MiCA",
                "gap": "Crypto-related operations insufficiently secured",
                "evidence": "Manipulation of crypto transaction flows can affect monitoring integrity",
                "severity": "high"
            },
            {
                "framework": "AI Act",
                "gap": "Insufficient auditability, traceability, and explainability of AI decisions",
                "evidence": "Poisoned feedback loop can alter decisions without clear explanation trail",
                "severity": "critical"
            },
            {
                "framework": "GDPR",
                "gap": "Weak governance over personal data used in logs and model pipelines",
                "evidence": "No strong lineage or governance evidence for personal data in AI pipeline",
                "severity": "medium"
            }
        ],
        "arms_failure_points": [
            "Weak validation of third-party transaction data",
            "Insufficient ML pipeline monitoring",
            "Lack of explainability and lineage evidence"
        ],
        "why_non_compliant": [
            "Critical ICT dependencies are insufficiently controlled",
            "Crypto flows are not adequately secured",
            "Automated decisions are not fully auditable or explainable",
            "Personal data governance is insufficiently evidenced"
        ],
        "recommended_controls": [
            "Strengthen API validation and integrity controls",
            "Implement data lineage and poisoning detection",
            "Improve decision traceability and explainability",
            "Increase third-party assurance and resilience testing"
        ]
    }

    agent = build_compliance_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Attack Agent output:
{attack_output}

Adversarial AI Agent output:
{ai_output}
"""

    return safe_run(agent, prompt, fallback_output)
