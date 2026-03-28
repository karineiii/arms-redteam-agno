from agno.agent import Agent
from agents.common import safe_run


def build_adversarial_ai_agent():
    return Agent(
        name="AdversarialAIAgent",
        instructions="""
You are the Adversarial AI Agent.

Mission:
- target the AI model or the data pipeline itself
- evaluate whether ARMS can be manipulated into incorrect decisions without service interruption

Return STRICT JSON only.
"""
    )


def run_adversarial_ai(recon_output: str):
    fallback_output = {
        "scenario_type": "ai_or_data_attack",
        "scenario_name": "Progressive poisoning of AI feedback loop",
        "targeted_model_or_pipeline": [
            "Fraud Detection Model",
            "Feedback loop",
            "Retraining data pipeline"
        ],
        "attack_vector": "Injection of mislabeled transaction samples over time",
        "steps": [
            "Identify feedback or retraining pathway",
            "Inject low-volume poisoned samples",
            "Shift the model decision boundary gradually",
            "Cause fraudulent behavior to be learned as normal"
        ],
        "manipulated_features": [
            "transaction_amount",
            "destination_risk_score",
            "customer_behavior_label"
        ],
        "expected_model_failure": "Fraudulent patterns are gradually classified as legitimate without outage",
        "detection_observed": "Low visibility due to missing provenance and drift controls",
        "critical_break_point": "Weak lineage, monitoring, and poisoning detection in the ML pipeline",
        "regulatory_relevance": ["AI Act", "DORA", "GDPR"]
    }

    agent = build_adversarial_ai_agent()

    prompt = f"""
Reconnaissance output:
{recon_output}

Design one realistic AI/data attack scenario against ARMS.
"""

    return safe_run(agent, prompt, fallback_output)
