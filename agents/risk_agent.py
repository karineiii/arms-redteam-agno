from agno.agent import Agent
from agents.common import to_text


def build_risk_agent():
    return Agent(
        name="ImpactRiskScoringAgent",
        instructions="""
You are the Impact & Risk Scoring Agent.

Mission:
- evaluate the consequences of the attacks on the institution
- quantify impact and prioritize vulnerabilities

Evaluate:
- estimated financial loss
- regulatory exposure
- reputational impact
- operational disruption
- prioritization of discovered vulnerabilities

Return STRICT JSON with:
{
  "global_risk_score": 0.0,
  "risk_level": "low|medium|high|critical",
  "financial_impact": "...",
  "regulatory_impact": "...",
  "reputational_impact": "...",
  "operational_impact": "...",
  "prioritized_vulnerabilities": [...],
  "executive_summary": "..."
}
Do not add markdown.
"""
    )


def run_risk(recon_output: str, attack_output: str, ai_output: str, compliance_output: str):
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

Produce a final impact and risk score for ARMS.
"""

    result = agent.run(prompt)
    return to_text(result)
