import json
import os
import re
from typing import Any

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import load_json, get_scenario


def build_recon_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    instructions = """
You are the Reconnaissance Agent of an agentic banking Red Team for ARMS
(Agentic Risk Monitoring System).

You analyze:
- system architecture
- internal components
- external vendors
- scenario-specific attack opportunities

You MUST return ONLY one valid JSON object.
No markdown.
No explanation.
No text before or after the JSON.

Your JSON MUST contain exactly these keys:
- target_systems
- critical_assets
- data_flows
- critical_dependencies
- entry_vectors
- attack_surface_map
- assumptions
- confidence_score
- scenario_context

STRICT REQUIREMENTS:
- Never return empty arrays
- Never use placeholders such as "Model-generated", "unknown", "N/A", "TBD"
- Be specific and realistic for a banking / AI / crypto compliance system
- Data flows must be meaningful and concrete
- Entry vectors must be plausible attack paths
- Attack surface must include API, data, AI/ML, third-party, and cloud exposure when relevant
- confidence_score must be a float between 0.0 and 1.0
"""

    return Agent(
        name="ReconnaissanceAgent",
        model=model,
        instructions=instructions,
    )


def strip_markdown_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_first_json_object(text: str) -> str:
    """
    Tries to extract the first top-level JSON object from a noisy LLM response.
    """
    cleaned = strip_markdown_fences(text)

    start = cleaned.find("{")
    if start == -1:
        raise ValueError("No JSON object start found.")

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(cleaned)):
        ch = cleaned[idx]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return cleaned[start : idx + 1]

    raise ValueError("No complete JSON object found.")


def try_parse_json(text: str) -> dict[str, Any]:
    candidate = extract_first_json_object(text)
    return json.loads(candidate)


def build_recon_seed(architecture: dict[str, Any], vendors: dict[str, Any], scenario: str) -> dict[str, Any]:
    components = architecture.get("components", [])
    vendor_items = vendors.get("vendors", [])

    component_names = [
        item.get("name")
        for item in components
        if isinstance(item, dict) and item.get("name")
    ]

    vendor_names = []
    for item in vendor_items:
        if isinstance(item, dict):
            vendor_names.append(
                item.get("name")
                or item.get("vendor")
                or item.get("service")
                or "External vendor"
            )
        else:
            vendor_names.append(str(item))

    target_systems = component_names[:]
    if not target_systems:
        target_systems = [
            "API Gateway",
            "Transaction Ingestion Pipeline",
            "Fraud Detection Model",
            "AML Monitoring Engine",
            "Crypto API Connector",
        ]

    critical_assets = components if components else [
        {"name": "API Gateway", "type": "service", "criticality": "high"},
        {"name": "Fraud Detection Model", "type": "ml_model", "criticality": "high"},
        {"name": "Transaction Database", "type": "database", "criticality": "high"},
        {"name": "Compliance Audit Logs", "type": "logging", "criticality": "high"},
    ]

    critical_dependencies = vendor_items if vendor_items else [
        {"name": "Cloud provider", "role": "hosting / compute"},
        {"name": "Crypto market API", "role": "external pricing / transaction context"},
        {"name": "Identity and access management", "role": "privileged access control"},
    ]

    data_flows = [
        {
            "source": "Client / Upstream Banking System",
            "target": "API Gateway",
            "description": "Incoming transaction and risk-related requests enter ARMS through exposed APIs."
        },
        {
            "source": "API Gateway",
            "target": "Transaction Ingestion Pipeline",
            "description": "Requests are normalized, validated, and forwarded for downstream analytics."
        },
        {
            "source": "Transaction Ingestion Pipeline",
            "target": "Fraud Detection Model",
            "description": "Transaction features and contextual signals are sent to the ML model for scoring."
        },
        {
            "source": "Fraud Detection Model",
            "target": "AML Monitoring Engine",
            "description": "Fraud scores and anomaly indicators are consumed by AML and risk controls."
        },
        {
            "source": "External Crypto API",
            "target": "Transaction Ingestion Pipeline",
            "description": "Third-party crypto market and wallet intelligence enrich transaction analysis."
        },
        {
            "source": "Decision / Alerting Components",
            "target": "Audit Logs / Compliance Storage",
            "description": "Decisions, alerts, and traceability artifacts are stored for audit and compliance review."
        },
    ]

    entry_vectors = [
        "Malicious payload injection through public or partner-facing API endpoints",
        "Compromise or manipulation of third-party crypto / data provider responses",
        "Adversarial inputs crafted to alter fraud model inference outcomes",
        "Privilege misuse through IAM or admin console misconfiguration",
        "Tampering with ingestion or feature engineering data before model scoring",
    ]

    attack_surface_map = [
        "Public-facing API Gateway and upstream integration endpoints",
        "Transaction ingestion and enrichment pipeline",
        "Fraud Detection Model inference interface",
        "AML Monitoring Engine decision pipeline",
        "Third-party crypto and external intelligence APIs",
        "Cloud IAM roles, secrets, and service-to-service permissions",
        "Centralized logging, audit, and monitoring systems",
    ]

    assumptions = [
        "ARMS is deployed in a cloud-hosted environment with multiple internal services.",
        "ARMS relies on external providers for crypto-related intelligence or transaction context.",
        "Fraud and AML decisions depend on the integrity of input features, model outputs, and audit traces.",
    ]

    if scenario == "api_attack":
        entry_vectors.append("Abuse of weak request validation or schema handling on exposed APIs")
        attack_surface_map.append("Rate limiting, auth, and request validation logic on external APIs")
        assumptions.append("API traffic is a primary operational entry point into ARMS.")

    elif scenario == "third_party_outage":
        entry_vectors.append("Operational disruption caused by dependency failure or degraded vendor availability")
        attack_surface_map.append("External dependency availability and failover mechanisms")
        assumptions.append("ARMS resilience depends on external provider continuity and graceful degradation.")

    elif scenario == "ai_poisoning":
        entry_vectors.append("Poisoned training, feedback, or labeled fraud data influencing model behavior")
        attack_surface_map.append("Training data curation, feedback loop, and retraining pipeline")
        assumptions.append("The model lifecycle includes data refresh, feedback loops, or retraining inputs.")

    elif scenario == "input_perturbation":
        entry_vectors.append("Subtle manipulation of transaction fields to evade model detection without system failure")
        attack_surface_map.append("Feature extraction and model pre-processing layer")
        assumptions.append("Small changes in input features can materially shift model predictions.")

    return {
        "target_systems": target_systems,
        "critical_assets": critical_assets,
        "data_flows": data_flows,
        "critical_dependencies": critical_dependencies,
        "entry_vectors": entry_vectors,
        "attack_surface_map": attack_surface_map,
        "assumptions": assumptions,
        "confidence_score": 0.86,
        "scenario_context": scenario,
    }


def normalize_list_of_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, str):
                text = item.strip()
                if text:
                    result.append(text)
            elif isinstance(item, dict):
                text = item.get("name") or item.get("description") or item.get("value")
                if isinstance(text, str) and text.strip():
                    result.append(text.strip())
        return result
    return []


def normalize_data_flows(value: Any) -> list[dict[str, str]]:
    flows = []

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                source = str(item.get("source", "")).strip()
                target = str(item.get("target", "")).strip()
                description = str(item.get("description", "")).strip()

                if source and target:
                    flows.append({
                        "source": source,
                        "target": target,
                        "description": description or f"Flow from {source} to {target}",
                    })

            elif isinstance(item, str):
                text = item.strip()
                if "->" in text:
                    parts = [p.strip() for p in text.split("->") if p.strip()]
                    if len(parts) >= 2:
                        flows.append({
                            "source": parts[0],
                            "target": parts[-1],
                            "description": text,
                        })
                elif text:
                    flows.append({
                        "source": "Unspecified source",
                        "target": "Unspecified target",
                        "description": text,
                    })

    return flows


def contains_bad_placeholder(value: Any) -> bool:
    bad_tokens = {
        "model-generated",
        "unknown",
        "n/a",
        "tbd",
        "placeholder",
        "not provided",
        "unspecified",
    }

    if isinstance(value, str):
        lowered = value.strip().lower()
        return any(token in lowered for token in bad_tokens)

    if isinstance(value, list):
        return any(contains_bad_placeholder(v) for v in value)

    if isinstance(value, dict):
        return any(contains_bad_placeholder(v) for v in value.values())

    return False


def validate_recon_output(data: dict[str, Any]) -> bool:
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

    if not isinstance(data, dict):
        return False

    for key in required_keys:
        if key not in data:
            return False

    if not isinstance(data["target_systems"], list) or len(data["target_systems"]) == 0:
        return False
    if not isinstance(data["critical_assets"], list) or len(data["critical_assets"]) == 0:
        return False
    if not isinstance(data["data_flows"], list) or len(data["data_flows"]) == 0:
        return False
    if not isinstance(data["critical_dependencies"], list) or len(data["critical_dependencies"]) == 0:
        return False
    if not isinstance(data["entry_vectors"], list) or len(data["entry_vectors"]) == 0:
        return False
    if not isinstance(data["attack_surface_map"], list) or len(data["attack_surface_map"]) == 0:
        return False
    if not isinstance(data["assumptions"], list) or len(data["assumptions"]) == 0:
        return False

    if contains_bad_placeholder(data):
        return False

    try:
        score = float(data["confidence_score"])
        if score < 0.0 or score > 1.0:
            return False
    except Exception:
        return False

    if not isinstance(data["scenario_context"], str) or not data["scenario_context"].strip():
        return False

    return True


def repair_recon_output(parsed: dict[str, Any], seed: dict[str, Any], scenario: str) -> dict[str, Any]:
    repaired = {}

    repaired["target_systems"] = normalize_list_of_strings(parsed.get("target_systems"))
    if not repaired["target_systems"] or contains_bad_placeholder(repaired["target_systems"]):
        repaired["target_systems"] = seed["target_systems"]

    repaired["critical_assets"] = parsed.get("critical_assets")
    if not isinstance(repaired["critical_assets"], list) or len(repaired["critical_assets"]) == 0:
        repaired["critical_assets"] = seed["critical_assets"]
    elif contains_bad_placeholder(repaired["critical_assets"]):
        repaired["critical_assets"] = seed["critical_assets"]

    repaired["data_flows"] = normalize_data_flows(parsed.get("data_flows"))
    if not repaired["data_flows"] or contains_bad_placeholder(repaired["data_flows"]):
        repaired["data_flows"] = seed["data_flows"]

    repaired["critical_dependencies"] = parsed.get("critical_dependencies")
    if not isinstance(repaired["critical_dependencies"], list) or len(repaired["critical_dependencies"]) == 0:
        repaired["critical_dependencies"] = seed["critical_dependencies"]
    elif contains_bad_placeholder(repaired["critical_dependencies"]):
        repaired["critical_dependencies"] = seed["critical_dependencies"]

    repaired["entry_vectors"] = normalize_list_of_strings(parsed.get("entry_vectors"))
    if not repaired["entry_vectors"] or contains_bad_placeholder(repaired["entry_vectors"]):
        repaired["entry_vectors"] = seed["entry_vectors"]

    repaired["attack_surface_map"] = normalize_list_of_strings(parsed.get("attack_surface_map"))
    if not repaired["attack_surface_map"] or contains_bad_placeholder(repaired["attack_surface_map"]):
        repaired["attack_surface_map"] = seed["attack_surface_map"]

    repaired["assumptions"] = normalize_list_of_strings(parsed.get("assumptions"))
    if not repaired["assumptions"] or contains_bad_placeholder(repaired["assumptions"]):
        repaired["assumptions"] = seed["assumptions"]

    try:
        repaired["confidence_score"] = float(parsed.get("confidence_score", seed["confidence_score"]))
    except Exception:
        repaired["confidence_score"] = seed["confidence_score"]

    if repaired["confidence_score"] < 0.0 or repaired["confidence_score"] > 1.0:
        repaired["confidence_score"] = seed["confidence_score"]

    scenario_context = parsed.get("scenario_context", "")
    if not isinstance(scenario_context, str) or not scenario_context.strip() or contains_bad_placeholder(scenario_context):
        repaired["scenario_context"] = scenario
    else:
        repaired["scenario_context"] = scenario_context.strip()

    return repaired


def build_prompt(architecture: dict[str, Any], vendors: dict[str, Any], scenario: str, seed: dict[str, Any]) -> str:
    return f"""
Scenario: {scenario}

System: ARMS (Agentic Risk Monitoring System)
Domain: Banking / Crypto / AI Compliance (DORA, MiCA, AI Act, GDPR)

ARMS architecture:
{json.dumps(architecture, indent=2, ensure_ascii=False)}

External vendors:
{json.dumps(vendors, indent=2, ensure_ascii=False)}

Reference baseline (use it to stay realistic, but enrich it):
{json.dumps(seed, indent=2, ensure_ascii=False)}

Return ONLY one valid JSON object with exactly these keys:
- target_systems
- critical_assets
- data_flows
- critical_dependencies
- entry_vectors
- attack_surface_map
- assumptions
- confidence_score
- scenario_context

Additional constraints:
- target_systems: list of strings
- critical_assets: list of objects or strings, but must be concrete and relevant
- data_flows: list of objects with source, target, description
- critical_dependencies: list of concrete external or internal dependencies
- entry_vectors: list of realistic attacker entry paths
- attack_surface_map: list of concrete exposed surfaces
- assumptions: list of explicit assumptions grounded in the architecture
- confidence_score: float between 0.0 and 1.0
- scenario_context: must match the scenario and mention scenario-specific exposure

Do not leave any field empty.
Do not use placeholders.
Do not wrap the JSON in markdown.
"""


def run_recon():
    architecture = load_json("data/architecture_arms.json")
    vendors = load_json("data/vendors.json")
    scenario = get_scenario()

    seed = build_recon_seed(architecture, vendors, scenario)

    use_fallback = os.getenv("USE_FALLBACK", "1").lower() in ("1", "true", "yes")
    if use_fallback:
        return json.dumps(seed, indent=2, ensure_ascii=False)

    agent = build_recon_agent()
    prompt = build_prompt(architecture, vendors, scenario, seed)

    try:
        result = agent.run(prompt)
        text = result.content if hasattr(result, "content") else str(result)

        parsed = try_parse_json(text)
        repaired = repair_recon_output(parsed, seed, scenario)

        if validate_recon_output(repaired):
            return json.dumps(repaired, indent=2, ensure_ascii=False)

        return json.dumps(seed, indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(seed, indent=2, ensure_ascii=False)
