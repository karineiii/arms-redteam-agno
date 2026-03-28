from agno.agent import Agent
from agents.common import to_text


def build_compliance_agent():
    return Agent(
        name="ComplianceBreakerAgent",
        instructions="""
You are the Compliance Breaker Agent.

Mission:
- formally identify regulatory breaches and compliance gaps
- translate technical findings into DORA, MiCA, AI Act and GDPR issues

Focus on:
- unmanaged critical external dependencies
- insecure crypto-related operations
- lack of traceability
- unjustifiable or non-explainable automated decisions
- poor documentation and auditability
- non-compliant personal data processing

Return STRICT JSON with:
{
  "identified_gaps": [
    {
      "framework": "...",
      "gap": "...",
      "evidence": "...",
      "severity": "low|medium|high|critical"
    }
  ],
  "arms_failure_points": [...],
  "why_non_compliant": [...],
  "recommended_controls": [...]
}
Do not add markdown.
"""
    )


def run_compliance(recon_output: str, attack_output: str, ai_output: str):
    agent = build_compliance_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Attack Agent output:
{attack_output}

Adversarial AI Agent output:
{ai_output}

Identify formal compliance gaps for DORA, MiCA, AI Act and GDPR.
"""

    result = agent.run(prompt)
    return to_text(result)
