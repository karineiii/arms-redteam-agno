import os

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import safe_run, get_scenario


def build_compliance_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="ComplianceBreakerAgent",
        model=model,
        instructions="""
You are the Compliance Breaker Agent.

Return ONLY one valid raw JSON object.
Do not use markdown.
Do not use code fences.
Do not write explanations.

Required keys:
- identified_gaps
- arms_failure_points
- why_non_compliant
- recommended_controls
"""
    )


def run_compliance(recon_output: str, attack_output: str, ai_output: str):
    scenario = get_scenario()

    if scenario == "api_attack":
        fallback_output = {
            "identified_gaps": [
                {
                    "framework": "DORA",
                    "gap": "Critical third-party dependency insufficiently controlled",
                    "evidence": "Crypto API connector is trusted without strong integrity assurance",
                    "severity": "high"
                },
                {
                    "framework": "MiCA",
                    "gap": "Crypto-related operations insufficiently secured",
                    "evidence": "Manipulation of crypto transaction flows affects monitoring integrity",
                    "severity": "high"
                }
            ],
            "arms_failure_points": [
                "Weak validation of third-party transaction data",
                "Insufficient monitoring of API trust boundaries"
            ],
            "why_non_compliant": [
                "Critical ICT dependencies are insufficiently controlled",
                "Crypto flows are not adequately secured"
            ],
            "recommended_controls": [
                "Strengthen API validation and integrity controls",
                "Add third-party assurance and transaction signing checks"
            ]
        }
    elif scenario == "third_party_outage":
        fallback_output = {
            "identified_gaps": [
                {
                    "framework": "DORA",
                    "gap": "Insufficient resilience against third-party service disruption",
                    "evidence": "Critical service outage degrades monitoring capability",
                    "severity": "high"
                },
                {
                    "framework": "MiCA",
                    "gap": "Operational continuity for crypto monitoring is insufficient",
                    "evidence": "Loss of crypto feed reduces visibility on critical operations",
                    "severity": "medium"
                }
            ],
            "arms_failure_points": [
                "Overdependence on external providers",
                "Weak fallback monitoring path"
            ],
            "why_non_compliant": [
                "Operational resilience is insufficiently demonstrated",
                "Third-party continuity controls are weak"
            ],
            "recommended_controls": [
                "Add fallback providers",
                "Test degraded-mode procedures",
                "Strengthen continuity plans"
            ]
        }
    elif scenario == "input_perturbation":
        fallback_output = {
            "identified_gaps": [
                {
                    "framework": "AI Act",
                    "gap": "Insufficient robustness of model decisions",
                    "evidence": "Small input changes can alter outcomes without alerting controls",
                    "severity": "high"
                },
                {
                    "framework": "DORA",
                    "gap": "Weak monitoring of adversarial manipulation risk",
                    "evidence": "Inference-time abuse is poorly detected",
                    "severity": "medium"
                }
            ],
            "arms_failure_points": [
                "Weak adversarial robustness at inference time",
                "Insufficient decision traceability"
            ],
            "why_non_compliant": [
                "Automated decisions are not robust enough",
                "Adversarial misuse is not sufficiently monitored"
            ],
            "recommended_controls": [
                "Add adversarial robustness tests",
                "Improve model monitoring and explainability"
            ]
        }
    else:
        fallback_output = {
            "identified_gaps": [
                {
                    "framework": "AI Act",
                    "gap": "Insufficient auditability, traceability, and explainability of AI decisions",
                    "evidence": "Poisoned feedback loop alters decisions without clear explanation trail",
                    "severity": "critical"
                },
                {
                    "framework": "GDPR",
                    "gap": "Weak governance over personal data in model pipelines",
                    "evidence": "No strong lineage evidence for personal data used in training",
                    "severity": "medium"
                },
                {
                    "framework": "DORA",
                    "gap": "Insufficient ICT monitoring for the AI pipeline",
                    "evidence": "Weak controls against poisoning and drift",
                    "severity": "high"
                }
            ],
            "arms_failure_points": [
                "Weak ML pipeline monitoring",
                "Lack of explainability and lineage evidence"
            ],
            "why_non_compliant": [
                "Automated decisions are not fully auditable or explainable",
                "Personal data governance is insufficiently evidenced",
                "AI pipeline resilience is too weak"
            ],
            "recommended_controls": [
                "Implement data lineage and poisoning detection",
                "Improve decision traceability and explainability",
                "Add model governance controls"
            ]
        }

    agent = build_compliance_agent()

    prompt = f"""
Scenario: {scenario}

Reconnaissance output:
{recon_output}

Attack output:
{attack_output}

AI output:
{ai_output}

Return ONLY one raw JSON object with the required keys.
"""

    required_keys = [
        "identified_gaps",
        "arms_failure_points",
        "why_non_compliant",
        "recommended_controls",
    ]

    return safe_run(
        agent,
        prompt,
        fallback_output,
        required_keys=required_keys,
        agent_type="compliance",
    )
