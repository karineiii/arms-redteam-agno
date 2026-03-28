from agno.agent import Agent
from agents.common import safe_run, get_scenario


def build_attack_agent():
    return Agent(
        name="AttackAgent",
        instructions="""
You are the Attack Agent of an agentic banking Red Team.
Return STRICT JSON only.
"""
    )


def run_attack(recon_output: str):
    scenario = get_scenario()

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

    elif scenario == "ai_poisoning":
        fallback_output = {
            "scenario_type": "supporting_cyber_condition",
            "scenario_name": "Feedback loop exposure enabling poisoning",
            "targeted_systems": [
                "Fraud Detection Model",
                "Retraining data pipeline"
            ],
            "steps": [
                "Identify retraining or feedback ingestion path",
                "Abuse weak control over feedback acceptance",
                "Allow poisoned labels to enter the ML pipeline"
            ],
            "injected_or_manipulated_data": [
                "mislabeled feedback samples",
                "corrupted training labels"
            ],
            "expected_system_behavior": "ARMS continues operation while model quality degrades over time",
            "detection_observed": "Low detection due to weak lineage and monitoring",
            "critical_break_point": "Untrusted feedback data enters the retraining path",
            "regulatory_relevance": ["AI Act", "DORA"],
            "severity": "high"
        }

    else:
        fallback_output = {
            "scenario_type": "supporting_cyber_condition",
            "scenario_name": "Inference-path manipulation condition",
            "targeted_systems": [
                "Fraud Detection Model",
                "Inference input layer"
            ],
            "steps": [
                "Target threshold-sensitive transaction features",
                "Exploit weak validation before scoring",
                "Enable subtle adversarial feature shifts"
            ],
            "injected_or_manipulated_data": [
                "borderline transaction features",
                "modified scoring inputs"
            ],
            "expected_system_behavior": "ARMS misclassifies some suspicious events",
            "detection_observed": "Low-confidence anomaly detection",
            "critical_break_point": "Weak inference input controls",
            "regulatory_relevance": ["AI Act", "DORA"],
            "severity": "medium"
        }

    agent = build_attack_agent()
    prompt = f"Reconnaissance output:\n{recon_output}"
    return safe_run(agent, prompt, fallback_output)
