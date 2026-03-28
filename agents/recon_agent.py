import json
import os

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import load_json, safe_run, get_scenario


def build_recon_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="ReconnaissanceAgent",
        model=model,
        instructions="""
You are the Reconnaissance Agent of an agentic banking Red Team.

You must analyze the ARMS architecture and external vendors.

Return ONLY one valid raw JSON object.
Do not use markdown.
Do not use code fences.
Do not write any explanation.
Do not write any text before or after the JSON.

The JSON must contain exactly these keys:
- target_systems
- critical_assets
- data_flows
- critical_dependencies
- entry_vectors
- attack_surface_map
- assumptions
- confidence_score
- scenario_context
"""
    )


def run_recon():
    architecture = load_json("data/architecture_arms.json")
    vendors = load_json("data/vendors.json")
    scenario = get_scenario()

    fallback_output = {
        "target_systems": [
            "API Gateway",
            "Transaction Ingestion Pipeline",
            "Fraud Detection Model",
            "AML Monitoring Engine",
            "Crypto API Connector"
        ],
        "critical_assets": architecture["components"],
        "data_flows": [
            {"source": "API Gateway", "target": "Transaction Ingestion Pipeline"},
            {"source": "Transaction Ingestion Pipeline", "target": "Fraud Detection Model"},
            {"source": "Fraud Detection Model", "target": "AML Monitoring Engine"}
        ],
        "critical_dependencies": vendors["vendors"],
        "entry_vectors": [
            "External API exposure",
            "Third-party crypto API connector",
            "Admin console misuse",
            "IAM misconfiguration"
        ],
        "attack_surface_map": [
            "Public-facing API layer",
            "Third-party crypto transaction ingestion",
            "Cloud IAM dependency",
            "Centralized logging dependency"
        ],
        "assumptions": [
            "ARMS depends on third-party APIs",
            "ARMS includes ML-based fraud detection",
            "Critical services are cloud-hosted"
        ],
        "confidence_score": 0.84,
        "scenario_context": scenario
    }

    if scenario == "third_party_outage":
        fallback_output["attack_surface_map"].append(
            "Operational dependency on external provider availability"
        )
        fallback_output["assumptions"].append(
            "Crypto monitoring visibility depends on external service continuity"
        )

    if scenario in ("ai_poisoning", "input_perturbation"):
        fallback_output["entry_vectors"].append(
            "ML feedback or inference manipulation"
        )
        fallback_output["attack_surface_map"].append(
            "Fraud model input and retraining pipeline"
        )
        fallback_output["assumptions"].append(
            "Model decisions depend on feature integrity and data lineage"
        )

    agent = build_recon_agent()

    prompt = f"""
Scenario: {scenario}

ARMS architecture:
{json.dumps(architecture, indent=2, ensure_ascii=False)}

External vendors:
{json.dumps(vendors, indent=2, ensure_ascii=False)}

Return ONLY one raw JSON object with exactly the requested keys.
"""

    required_keys = [
        "target_systems",
        "critical_assets",
        "data_flows",
        "critical_dependencies",
        "entry_vectors",
        "attack_surface_map",
        "assumptions",
        "confidence_score",
        "scenario_context",
    ]

    return safe_run(agent, prompt, fallback_output, required_keys=required_keys)
