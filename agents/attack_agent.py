import os
from agno.agent import Agent
from agents.common import safe_run


def build_attack_agent():
    return Agent(
        name="AttackAgent",
        instructions="""
You are the Attack Agent of an agentic banking Red Team.
Return STRICT JSON only.
"""
    )


def run_attack(recon_output: str):
    scenario = os.getenv("SCENARIO", "api_attack")

    if scenario == "api_attack":
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
            "regulatory_relevance": ["DORA", "MiCA"],
            "severity": "high"
        }

    elif scenario == "third_party_outage":
        fallback_output = {
            "scenario_type": "conventional_cyber_attack",
            "scenario_name": "Critical third-party outage and degraded monitoring",
            "targeted_systems": [
                "Crypto API Connector",
                "Central Logging",
                "AML Monitoring Engine"
            ],
            "steps": [
                "Disrupt critical third-party feed",
                "Create incomplete transaction visibility",
                "Degrade fraud and AML monitoring coverage"
            ],
            "injected_or_manipulated_data": [
                "missing transaction feeds",
                "incomplete logging",
                "delayed alerts"
            ],
            "expected_system_behavior": "ARMS loses part of its visibility on crypto-related transactions",
            "detection_observed": "Late detection through logging inconsistencies",
            "critical_break_point": "Overdependence on a critical external provider",
            "regulatory_relevance": ["DORA", "MiCA"],
            "severity": "medium"
        }

    else:
        fallback_output = {
            "scenario_type": "conventional_cyber_attack",
            "scenario_name": "Generic transaction manipulation",
            "targeted_systems": ["API Gateway"],
            "steps": [
                "Send deceptive transaction events",
                "Exploit weak validation logic"
            ],
            "injected_or_manipulated_data": [
                "transaction payloads",
                "risk flags"
            ],
            "expected_system_behavior": "ARMS misclassifies some events",
            "detection_observed": "Low-confidence anomaly detection",
            "critical_break_point": "Weak transaction controls",
            "regulatory_relevance": ["DORA"],
            "severity": "medium"
        }

    agent = build_attack_agent()
    prompt = f"Reconnaissance output:\n{recon_output}"
    return safe_run(agent, prompt, fallback_output)
