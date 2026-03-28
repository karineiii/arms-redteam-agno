import os
from agno.agent import Agent
from agents.common import safe_run


def build_adversarial_ai_agent():
    return Agent(
        name="AdversarialAIAgent",
        instructions="""
You are the Adversarial AI Agent.
Return STRICT JSON only.
"""
    )


def run_adversarial_ai(recon_output: str):
    scenario = os.getenv("SCENARIO", "ai_poisoning")

    if scenario == "ai_poisoning":
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
            "regulatory_relevance": ["AI Act", "DORA", "GDPR"],
            "severity": "critical"
        }

    elif scenario == "input_perturbation":
        fallback_output = {
            "scenario_type": "ai_or_data_attack",
            "scenario_name": "Subtle input perturbation attack",
            "targeted_model_or_pipeline": [
                "Fraud Detection Model",
                "Inference input layer"
            ],
            "attack_vector": "Small changes to transaction features to cross model thresholds",
            "steps": [
                "Identify decision threshold sensitive features",
                "Modify low-signal transaction attributes",
                "Push suspicious events below alert threshold"
            ],
            "manipulated_features": [
                "amount",
                "frequency",
                "destination score"
            ],
            "expected_model_failure": "Borderline fraudulent events evade detection",
            "detection_observed": "Very limited detection due to subtle feature drift",
            "critical_break_point": "Lack of robust inference-time adversarial controls",
            "regulatory_relevance": ["AI Act", "DORA"],
            "severity": "high"
        }

    else:
        fallback_output = {
            "scenario_type": "ai_or_data_attack",
            "scenario_name": "Bias induction in fraud detection",
            "targeted_model_or_pipeline": [
                "Fraud Detection Model"
            ],
            "attack_vector": "Manipulation of historical labels to shift detection bias",
            "steps": [
                "Alter historical labels",
                "Trigger biased retraining",
                "Reduce detection quality for selected categories"
            ],
            "manipulated_features": [
                "historical labels",
                "training distribution"
            ],
            "expected_model_failure": "Uneven detection across transaction categories",
            "detection_observed": "Delayed detection through fairness degradation indicators",
            "critical_break_point": "Weak training data governance",
            "regulatory_relevance": ["AI Act", "GDPR"],
            "severity": "high"
        }

    agent = build_adversarial_ai_agent()
    prompt = f"Reconnaissance output:\n{recon_output}"
    return safe_run(agent, prompt, fallback_output)
