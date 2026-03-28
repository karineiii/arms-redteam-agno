import json
from agno.agent import Agent
from agents.common import load_json, safe_run, get_scenario


def build_recon_agent():
    return Agent(
        name="ReconnaissanceAgent",
        instructions="""
You are the Reconnaissance Agent of an agentic banking Red Team.

Mission:
- identify critical dependencies of ARMS
- map sensitive data flows
- identify entry vectors
- identify critical third-party providers
- build a detailed attack surface map

Return STRICT JSON only.
"""
    )


def run_recon():
    architecture = load_json("data/architecture_arms.json")
    vendors = load_json("data/vendors.json")
    scenario = get_scenario()

    entry_vectors = [
        "External API exposure",
        "Third-party crypto API connector",
        "Admin console misuse",
        "IAM misconfiguration"
    ]

    attack_surface_map = [
        "Public-facing API layer",
        "Third-party crypto transaction ingestion",
        "Cloud IAM dependency",
        "Centralized logging dependency"
    ]

    assumptions = [
        "ARMS depends on third-party APIs",
        "ARMS includes ML-based fraud detection",
        "Critical services are cloud-hosted"
    ]

    if scenario == "third_party_outage":
        attack_surface_map.append("Operational dependency on external provider availability")
        assumptions.append("Crypto monitoring visibility depends on external service continuity")

    if scenario in ("ai_poisoning", "input_perturbation"):
        entry_vectors.append("ML feedback or inference manipulation")
        attack_surface_map.append("Fraud model input and retraining pipeline")
        assumptions.append("Model decisions depend on feature integrity and data lineage")

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
        "entry_vectors": entry_vectors,
        "attack_surface_map": attack_surface_map,
        "assumptions": assumptions,
        "confidence_score": 0.84,
        "scenario_context": scenario
    }

    agent = build_recon_agent()

    prompt = f"""
Scenario:
{scenario}

ARMS architecture:
{json.dumps(architecture, indent=2, ensure_ascii=False)}

External vendors:
{json.dumps(vendors, indent=2, ensure_ascii=False)}
"""

    return safe_run(agent, prompt, fallback_output)
