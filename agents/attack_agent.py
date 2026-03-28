from agno.agent import Agent
from agents.common import to_text


def build_attack_agent():
    return Agent(
        name="AttackAgent",
        instructions="""
You are the Attack Agent of an agentic banking Red Team.

Mission:
- simulate a high-probability cyber attack
- focus on realistic attack paths against ARMS
- test robustness of ARMS to injected or manipulated data

Examples:
- transaction data manipulation
- false signal injection to bypass AML controls
- exploitation of crypto API weaknesses

Return STRICT JSON with:
{
  "scenario_type": "conventional_cyber_attack",
  "scenario_name": "...",
  "targeted_systems": [...],
  "steps": [...],
  "injected_or_manipulated_data": [...],
  "expected_system_behavior": "...",
  "detection_observed": "...",
  "critical_break_point": "...",
  "regulatory_relevance": [...]
}
Do not add markdown.
"""
    )


def run_attack(recon_output: str):
    agent = build_attack_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Select one realistic conventional cyber scenario against ARMS.
Focus on API/payment/crypto transaction manipulation and probable abuse paths.
"""

    result = agent.run(prompt)
    return to_text(result)
