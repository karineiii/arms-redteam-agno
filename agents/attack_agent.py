from agno.agent import Agent
from agents.common import safe_run


def build_attack_agent():
    return Agent(
        name="AttackAgent",
        instructions="""
You are the Attack Agent of an agentic banking Red Team.

Mission:
- simulate a high-probability cyber attack
- focus on realistic attack paths against ARMS
- test robustness of ARMS to injected or manipulated data

Return STRICT JSON only.
"""
    )


def run_attack(recon_output: str):
    fallback_output = {
        "scenario_type": "conventional_cyber_attack",
        "scenario_name": "Compromise of payment or crypto API",
        "targeted_systems": [
            "API Gateway",
            "Crypto API Connector",
            "Transaction Ingestion Pipeline"
        ],
        "steps": [
            "Map exposed API endpoints",
            "Abuse weak validation on third-party connector",
            "Inject plausible but malicious transaction payloads",
            "Influence AML and fraud monitoring decisions"
        ],
        "injected_or_manipulated_data": [
            "transaction amount",
            "destination wallet",
            "transaction frequency",
            "risk attributes"
        ],
        "expected_system_behavior": "ARMS continues running but produces false negatives in monitoring",
        "detection_observed": "Partial detection only through anomalous API usage patterns",
        "critical_break_point": "Insufficient integrity validation of incoming third-party transaction data",
        "regulatory_relevance": ["DORA", "MiCA"]
    }

    agent = build_attack_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Select one realistic conventional cyber scenario against ARMS.
"""

    return safe_run(agent, prompt, fallback_output)
