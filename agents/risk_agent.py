import os
from agno.agent import Agent
from agents.common import safe_run


def build_risk_agent():
    return Agent(
        name="ImpactRiskScoringAgent",
        instructions="""
You are the Impact & Risk Scoring Agent.
Return STRICT JSON only.
"""
    )


def run_risk(recon_output: str, attack_output: str, ai_output: str, compliance_output: str):
    scenario = os.getenv("SCENARIO", "api_attack")

    if scenario == "api_attack":
        fallback_output = {
            "global_risk_score": 0.82,
            "risk_level": "critical",
            "financial_impact": "high",
            "regulatory_impact": "high",
            "reputational_impact": "high",
            "operational_impact": "high",
            "prioritized_vulnerabilities": [
                "Critical external API dependency not sufficiently controlled",
                "Weak transaction integrity validation",
                "Insufficient third-party assurance"
            ],
            "executive_summary": "ARMS presents a critical risk due to exposure to malicious transaction injection through a trusted crypto/payment interface."
        }

    elif scenario == "third_party_outage":
        fallback_output = {
            "global_risk_score": 0.67,
            "risk_level": "high",
            "financial_impact": "medium",
            "regulatory_impact": "high",
            "reputational_impact": "medium",
            "operational_impact": "high",
            "prioritized_vulnerabilities": [
                "Overdependence on a critical provider",
                "Weak degraded-mode monitoring",
                "Insufficient resilience testing"
            ],
            "executive_summary": "ARMS shows high operational risk when a critical third-party feed becomes unavailable."
        }

    elif scenario == "input_perturbation":
        fallback_output = {
            "global_risk_score": 0.74,
            "risk_level": "high",
            "financial_impact": "medium",
            "regulatory_impact": "high",
            "reputational_impact": "medium",
            "operational_impact": "medium",
            "prioritized_vulnerabilities": [
                "Weak inference-time robustness",
                "Insufficient adversarial input detection",
                "Limited explainability of borderline decisions"
            ],
            "executive_summary": "ARMS is vulnerable to subtle adversarial feature manipulation that degrades fraud detection quality."
        }

    else:
        fallback_output = {
            "global_risk_score": 0.91,
            "risk_level": "critical",
            "financial_impact": "high",
            "regulatory_impact": "high",
            "reputational_impact": "high",
            "operational_impact": "high",
            "prioritized_vulnerabilities": [
                "AI pipeline vulnerable to poisoning",
                "Weak data lineage and governance",
                "Insufficient monitoring of retraining inputs"
            ],
            "executive_summary": "ARMS presents critical risk because poisoned feedback data can silently corrupt model behavior over time."
        }

    agent = build_risk_agent()
    prompt = f"Recon:\n{recon_output}\n\nAttack:\n{attack_output}\n\nAI:\n{ai_output}\n\nCompliance:\n{compliance_output}"
    return safe_run(agent, prompt, fallback_output)
