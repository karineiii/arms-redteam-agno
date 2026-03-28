import json
from agno.agent import Agent
from agents.common import load_json, to_text


def build_recon_agent():
    return Agent(
        name="ReconnaissanceAgent",
        instructions="""
You are the Reconnaissance Agent of an agentic banking Red Team.

Mission:
- identify critical dependencies of ARMS
- map sensitive data flows
- identify possible entry vectors
- identify critical third-party providers
- build a detailed attack surface map

Inputs:
- ARMS architecture
- external vendors list

Return STRICT JSON with:
{
  "target_systems": [...],
  "critical_assets": [...],
  "data_flows": [...],
  "critical_dependencies": [...],
  "entry_vectors": [...],
  "attack_surface_map": [...],
  "assumptions": [...],
  "confidence_score": 0.0
}
Do not add markdown.
"""
    )


def run_recon():
    architecture = load_json("data/architecture_arms.json")
    vendors = load_json("data/vendors.json")

    agent = build_recon_agent()

    prompt = f"""
ARMS architecture:
{json.dumps(architecture, indent=2, ensure_ascii=False)}

External vendors:
{json.dumps(vendors, indent=2, ensure_ascii=False)}
"""

    result = agent.run(prompt)
    return to_text(result)
