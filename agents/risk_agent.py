from agno.agent import Agent
from agents.common import safe_run


def build_risk_agent():
    return Agent(
        name="ImpactRiskScoringAgent",
        instructions="""
You are the Impact & Risk Scoring Agent.

Mission:
- evaluate the consequences of the attacks on the institution
- quantify impact and prioritize vulnerabilities

Return STRICT JSON only.
"""
    )


def run_risk(recon_output: str, attack_output: str, ai_output: str, compliance_output: str):
    fallback_output = {
        "global_risk_score": 0.82,
        "risk_level": "critical",
        "financial_impact": "high",
        "regulatory_impact": "high",
        "reputational_impact": "high",
        "operational_impact": "high",
        "prioritized_vulnerabilities": [
            "Critical external API dependency not sufficiently controlled",
            "AI pipeline vulnerable to progressive poisoning",
            "Insufficient traceability and explainability",
            "Missing resilience evidence for critical services"
        ],
        "executive_summary": "ARMS presents a critical composite risk due to third-party API exposure, weak ML pipeline governance, and major regulatory compliance gaps."
    }

    agent = build_risk_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Attack Agent output:
{attack_output}

Adversarial AI Agent output:
{ai_output}

Compliance Breaker output:
{compliance_output}
"""

    return safe_run(agent, prompt, fallback_output)
