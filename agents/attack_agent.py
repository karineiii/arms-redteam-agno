import json
import os
import re
from typing import Any

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import get_scenario


def build_attack_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="AttackAgent",
        model=model,
        instructions="""
You are the Attack Agent of an agentic banking Red Team.

Your task is to produce ONE conventional or supporting cyber attack scenario
that is realistic for a banking / crypto / AI monitoring environment.

Return ONLY one valid JSON object.
No markdown.
No explanations.
No extra text.

Required keys:
- scenario_type
- scenario_name
- attack_preconditions
- business_objective_of_attacker
- targeted_systems
- steps
- injected_or_manipulated_data
- expected_system_behavior
- detection_observed
- critical_break_point
- regulatory_relevance
- severity

STRICT RULES:
- scenario_type must be one of:
  conventional_cyber_attack, supporting_cyber_condition
- attack_preconditions must be a non-empty list of concrete conditions
- business_objective_of_attacker must be a specific business goal
- targeted_systems must be a non-empty list
- steps must be a non-empty list of attack actions
- injected_or_manipulated_data must be a non-empty list
- regulatory_relevance must only contain framework names such as DORA, MiCA, AI Act, GDPR
- severity must be one of: low, medium, high, critical
- detection_observed must be a short string, not a list
- be concrete and realistic for ARMS
"""
    )


def strip_markdown_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_first_json_object(text: str) -> str:
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


def normalize_list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    result = []
    for item in value:
        if isinstance(item, str):
            text = item.strip()
            if text:
                result.append(text)
    return result


def build_fallback_output(scenario: str) -> dict[str, Any]:
    if scenario == "api_attack":
        return {
            "scenario_type": "conventional_cyber_attack",
            "scenario_name": "Compromise of payment or crypto API",
            "attack_preconditions": [
                "Public or partner-facing API endpoints are reachable by the attacker",
                "Input validation on external transaction payloads is weak or inconsistent",
                "ARMS trusts third-party crypto or payment data without strong integrity verification"
            ],
            "business_objective_of_attacker": "Inject fraudulent crypto or payment transactions and bypass AML and fraud monitoring controls",
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

    if scenario == "third_party_outage":
        return {
            "scenario_type": "conventional_cyber_attack",
            "scenario_name": "Critical third-party outage and degraded monitoring",
            "attack_preconditions": [
                "ARMS depends on a critical third-party provider for crypto transaction visibility",
                "Failover and redundancy controls are limited or insufficiently tested",
                "Monitoring quality depends on the availability and integrity of external feeds"
            ],
            "business_objective_of_attacker": "Reduce transaction visibility and weaken AML and fraud monitoring by disrupting a critical external dependency",
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

    if scenario == "ai_poisoning":
        return {
            "scenario_type": "supporting_cyber_condition",
            "scenario_name": "Feedback loop exposure enabling poisoning",
            "attack_preconditions": [
                "The fraud model accepts retraining or feedback data from operational sources",
                "Controls on training data lineage and validation are weak",
                "Poisoned or mislabeled samples can enter the ML lifecycle without rapid detection"
            ],
            "business_objective_of_attacker": "Corrupt the model over time so that suspicious transactions are increasingly treated as legitimate",
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

    return {
        "scenario_type": "supporting_cyber_condition",
        "scenario_name": "Inference-path manipulation condition",
        "attack_preconditions": [
            "The attacker can influence transaction features before inference",
            "Feature validation and anomaly controls before model scoring are limited",
            "Decision thresholds are sensitive to small input changes"
        ],
        "business_objective_of_attacker": "Cause suspicious transactions to be misclassified without interrupting ARMS operations",
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


def repair_attack_output(parsed: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    repaired = {}

    allowed_types = {"conventional_cyber_attack", "supporting_cyber_condition"}
    allowed_severity = {"low", "medium", "high", "critical"}
    allowed_frameworks = {"DORA", "MiCA", "AI Act", "GDPR"}

    scenario_type = str(parsed.get("scenario_type", "")).strip()
    repaired["scenario_type"] = scenario_type if scenario_type in allowed_types else fallback["scenario_type"]

    scenario_name = str(parsed.get("scenario_name", "")).strip()
    repaired["scenario_name"] = scenario_name if scenario_name and not contains_bad_placeholder(scenario_name) else fallback["scenario_name"]

    attack_preconditions = normalize_list_of_strings(parsed.get("attack_preconditions"))
    repaired["attack_preconditions"] = attack_preconditions if attack_preconditions and not contains_bad_placeholder(attack_preconditions) else fallback["attack_preconditions"]

    business_objective = str(parsed.get("business_objective_of_attacker", "")).strip()
    repaired["business_objective_of_attacker"] = (
        business_objective
        if business_objective and not contains_bad_placeholder(business_objective)
        else fallback["business_objective_of_attacker"]
    )

    targeted_systems = normalize_list_of_strings(parsed.get("targeted_systems"))
    repaired["targeted_systems"] = targeted_systems if targeted_systems and not contains_bad_placeholder(targeted_systems) else fallback["targeted_systems"]

    steps = normalize_list_of_strings(parsed.get("steps"))
    repaired["steps"] = steps if steps and not contains_bad_placeholder(steps) else fallback["steps"]

    injected_data = normalize_list_of_strings(parsed.get("injected_or_manipulated_data"))
    repaired["injected_or_manipulated_data"] = injected_data if injected_data and not contains_bad_placeholder(injected_data) else fallback["injected_or_manipulated_data"]

    expected_behavior = str(parsed.get("expected_system_behavior", "")).strip()
    repaired["expected_system_behavior"] = (
        expected_behavior
        if expected_behavior and not contains_bad_placeholder(expected_behavior)
        else fallback["expected_system_behavior"]
    )

    detection_observed = parsed.get("detection_observed", "")
    if isinstance(detection_observed, list):
        detection_observed = ", ".join([str(x).strip() for x in detection_observed if str(x).strip()])
    detection_observed = str(detection_observed).strip()
    repaired["detection_observed"] = (
        detection_observed
        if detection_observed and not contains_bad_placeholder(detection_observed)
        else fallback["detection_observed"]
    )

    critical_break_point = str(parsed.get("critical_break_point", "")).strip()
    repaired["critical_break_point"] = (
        critical_break_point
        if critical_break_point and not contains_bad_placeholder(critical_break_point)
        else fallback["critical_break_point"]
    )

    regulatory_relevance = normalize_list_of_strings(parsed.get("regulatory_relevance"))
    regulatory_relevance = [x for x in regulatory_relevance if x in allowed_frameworks]
    repaired["regulatory_relevance"] = regulatory_relevance if regulatory_relevance else fallback["regulatory_relevance"]

    severity = str(parsed.get("severity", "")).strip().lower()
    repaired["severity"] = severity if severity in allowed_severity else fallback["severity"]

    return repaired


def validate_attack_output(data: dict[str, Any], scenario: str) -> bool:
    required_keys = [
        "scenario_type",
        "scenario_name",
        "attack_preconditions",
        "business_objective_of_attacker",
        "targeted_systems",
        "steps",
        "injected_or_manipulated_data",
        "expected_system_behavior",
        "detection_observed",
        "critical_break_point",
        "regulatory_relevance",
        "severity",
    ]

    if not isinstance(data, dict):
        return False

    for key in required_keys:
        if key not in data:
            return False

    if data["scenario_type"] not in {"conventional_cyber_attack", "supporting_cyber_condition"}:
        return False

    if not isinstance(data["scenario_name"], str) or not data["scenario_name"].strip():
        return False

    bad_scenario_names = {
        "api_attack",
        "third_party_outage",
        "ai_poisoning",
        "input_perturbation",
        "attack",
        "scenario",
    }
    if data["scenario_name"].strip().lower() in bad_scenario_names:
        return False

    if not isinstance(data["attack_preconditions"], list) or len(data["attack_preconditions"]) == 0:
        return False
    if not isinstance(data["targeted_systems"], list) or len(data["targeted_systems"]) == 0:
        return False
    if not isinstance(data["steps"], list) or len(data["steps"]) < 3:
        return False
    if not isinstance(data["injected_or_manipulated_data"], list) or len(data["injected_or_manipulated_data"]) == 0:
        return False
    if not isinstance(data["regulatory_relevance"], list) or len(data["regulatory_relevance"]) == 0:
        return False

    if data["severity"] not in {"low", "medium", "high", "critical"}:
        return False

    if not isinstance(data["detection_observed"], str) or not data["detection_observed"].strip():
        return False

    if not isinstance(data["business_objective_of_attacker"], str) or not data["business_objective_of_attacker"].strip():
        return False

    if not isinstance(data["expected_system_behavior"], str) or not data["expected_system_behavior"].strip():
        return False

    if not isinstance(data["critical_break_point"], str) or not data["critical_break_point"].strip():
        return False

    if contains_bad_placeholder(data):
        return False

    steps_text = " ".join(data["steps"]).lower()
    if scenario == "api_attack":
        required_frameworks = {"DORA", "MiCA"}
        if set(data["regulatory_relevance"]) != required_frameworks:
            return False
        if "api" not in data["scenario_name"].lower() and "crypto" not in data["scenario_name"].lower():
            return False
        if "inject" not in steps_text and "payload" not in steps_text:
            return False

    elif scenario == "third_party_outage":
        required_frameworks = {"DORA", "MiCA"}
        if set(data["regulatory_relevance"]) != required_frameworks:
            return False

    elif scenario == "ai_poisoning":
        required_frameworks = {"AI Act", "DORA"}
        if set(data["regulatory_relevance"]) != required_frameworks:
            return False

    else:
        required_frameworks = {"AI Act", "DORA"}
        if set(data["regulatory_relevance"]) != required_frameworks:
            return False

    return True

def run_attack(recon_output: str):
    scenario = get_scenario()
    fallback_output = build_fallback_output(scenario)

    use_fallback = os.getenv("USE_FALLBACK", "0").lower() in ("1", "true", "yes")
    if use_fallback:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    agent = build_attack_agent()

    prompt = f"""
Scenario: {scenario}

Reconnaissance output:
{recon_output}

Return ONLY one raw JSON object with exactly these keys:
- scenario_type
- scenario_name
- attack_preconditions
- business_objective_of_attacker
- targeted_systems
- steps
- injected_or_manipulated_data
- expected_system_behavior
- detection_observed
- critical_break_point
- regulatory_relevance
- severity

Important:
- scenario_type must be conventional_cyber_attack or supporting_cyber_condition
- regulatory_relevance must contain only framework names like DORA, MiCA, AI Act, GDPR
- severity must be lowercase
- detection_observed must be a string
"""

    try:
        result = agent.run(prompt)
        text = result.content if hasattr(result, "content") else str(result)

        parsed = try_parse_json(text)
        repaired = repair_attack_output(parsed, fallback_output)

        if validate_attack_output(repaired, scenario):
            return json.dumps(repaired, indent=2, ensure_ascii=False)

        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
