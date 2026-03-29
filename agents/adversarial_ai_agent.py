import json
import os
import re
from typing import Any

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import get_scenario


def build_ai_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="AdversarialAIAgent",
        model=model,
        instructions="""
You are the Adversarial AI Agent of an agentic banking Red Team.

Your task is to describe ONE realistic attack targeting the AI or data layer of ARMS.

Return ONLY one valid JSON object.
No markdown.
No explanations.
No extra text.

Required keys:
- scenario_type
- scenario_name
- targeted_model_or_pipeline
- attack_vector
- steps
- manipulated_features
- stealthiness
- decision_degradation_type
- expected_model_failure
- detection_observed
- critical_break_point
- regulatory_relevance
- severity

STRICT RULES:
- scenario_type must be ai_or_data_attack
- targeted_model_or_pipeline must be a non-empty list
- steps must be a non-empty list
- manipulated_features must be a non-empty list
- stealthiness must be one of: low, medium, high
- decision_degradation_type must describe how the model silently degrades
- regulatory_relevance must only contain framework names such as AI Act, GDPR, DORA
- severity must be one of: low, medium, high, critical
- outputs must be realistic for fraud detection / AML / banking AI systems
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
    if scenario == "ai_poisoning":
        return {
            "scenario_type": "ai_or_data_attack",
            "scenario_name": "Bias induction in fraud detection",
            "targeted_model_or_pipeline": [
                "Fraud Detection Model",
                "Retraining data pipeline"
            ],
            "attack_vector": "Manipulation of historical labels and poisoned feedback samples to shift fraud detection behavior",
            "steps": [
                "Identify retraining or feedback ingestion path",
                "Inject poisoned labels or biased feedback examples",
                "Trigger retraining or feedback incorporation",
                "Shift model behavior toward false negatives on suspicious transactions"
            ],
            "manipulated_features": [
                "historical labels",
                "training distribution",
                "feedback samples",
                "risk classification labels"
            ],
            "stealthiness": "high",
            "decision_degradation_type": "False negatives increase on suspicious crypto or payment transactions without interrupting service",
            "expected_model_failure": "The model silently becomes less effective at detecting suspicious patterns in selected transaction categories",
            "detection_observed": "Delayed detection through fairness, drift, or model quality degradation indicators",
            "critical_break_point": "Weak training data governance allows poisoned inputs into the model lifecycle",
            "regulatory_relevance": ["AI Act", "GDPR", "DORA"],
            "severity": "high"
        }

    return {
        "scenario_type": "ai_or_data_attack",
        "scenario_name": "Subtle inference-time feature perturbation",
        "targeted_model_or_pipeline": [
            "Fraud Detection Model",
            "Inference pre-processing layer"
        ],
        "attack_vector": "Small adversarial changes to sensitive transaction features near decision thresholds",
        "steps": [
            "Identify threshold-sensitive transaction features",
            "Craft subtle feature perturbations that remain operationally plausible",
            "Submit manipulated transactions through normal scoring paths",
            "Increase false negatives without triggering immediate system failure"
        ],
        "manipulated_features": [
            "transaction amount buckets",
            "destination risk indicators",
            "frequency-derived features",
            "behavioral anomaly features"
        ],
        "stealthiness": "high",
        "decision_degradation_type": "Borderline suspicious transactions are increasingly classified as legitimate while the service stays online",
        "expected_model_failure": "The model misclassifies suspicious events due to small but strategically chosen input shifts",
        "detection_observed": "Weak or delayed detection through subtle anomaly patterns and post-hoc review",
        "critical_break_point": "Weak inference input controls allow adversarial feature manipulation before model scoring",
        "regulatory_relevance": ["AI Act", "DORA"],
        "severity": "high"
    }


def repair_ai_output(parsed: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    repaired = {}

    repaired["scenario_type"] = "ai_or_data_attack"

    scenario_name = str(parsed.get("scenario_name", "")).strip()
    repaired["scenario_name"] = scenario_name if scenario_name and not contains_bad_placeholder(scenario_name) else fallback["scenario_name"]

    targeted = normalize_list_of_strings(parsed.get("targeted_model_or_pipeline"))
    repaired["targeted_model_or_pipeline"] = targeted if targeted and not contains_bad_placeholder(targeted) else fallback["targeted_model_or_pipeline"]

    attack_vector = str(parsed.get("attack_vector", "")).strip()
    repaired["attack_vector"] = attack_vector if attack_vector and not contains_bad_placeholder(attack_vector) else fallback["attack_vector"]

    steps = normalize_list_of_strings(parsed.get("steps"))
    repaired["steps"] = steps if steps and not contains_bad_placeholder(steps) else fallback["steps"]

    features = normalize_list_of_strings(parsed.get("manipulated_features"))
    repaired["manipulated_features"] = features if features and not contains_bad_placeholder(features) else fallback["manipulated_features"]

    stealthiness = str(parsed.get("stealthiness", "")).strip().lower()
    repaired["stealthiness"] = stealthiness if stealthiness in {"low", "medium", "high"} else fallback["stealthiness"]

    degradation = str(parsed.get("decision_degradation_type", "")).strip()
    repaired["decision_degradation_type"] = (
        degradation if degradation and not contains_bad_placeholder(degradation)
        else fallback["decision_degradation_type"]
    )

    expected_failure = str(parsed.get("expected_model_failure", "")).strip()
    repaired["expected_model_failure"] = (
        expected_failure if expected_failure and not contains_bad_placeholder(expected_failure)
        else fallback["expected_model_failure"]
    )

    detection = parsed.get("detection_observed", "")
    if isinstance(detection, list):
        detection = ", ".join([str(x).strip() for x in detection if str(x).strip()])
    detection = str(detection).strip()
    repaired["detection_observed"] = detection if detection and not contains_bad_placeholder(detection) else fallback["detection_observed"]

    break_point = str(parsed.get("critical_break_point", "")).strip()
    repaired["critical_break_point"] = break_point if break_point and not contains_bad_placeholder(break_point) else fallback["critical_break_point"]

    frameworks = normalize_list_of_strings(parsed.get("regulatory_relevance"))
    allowed_frameworks = {"AI Act", "GDPR", "DORA"}
    frameworks = [x for x in frameworks if x in allowed_frameworks]
    repaired["regulatory_relevance"] = frameworks if frameworks else fallback["regulatory_relevance"]

    severity = str(parsed.get("severity", "")).strip().lower()
    repaired["severity"] = severity if severity in {"low", "medium", "high", "critical"} else fallback["severity"]

    return repaired


def validate_ai_output(data: dict[str, Any], scenario: str) -> bool:
    required_keys = [
        "scenario_type",
        "scenario_name",
        "targeted_model_or_pipeline",
        "attack_vector",
        "steps",
        "manipulated_features",
        "stealthiness",
        "decision_degradation_type",
        "expected_model_failure",
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

    if data["scenario_type"] != "ai_or_data_attack":
        return False
    if not isinstance(data["scenario_name"], str) or not data["scenario_name"].strip():
        return False
    if not isinstance(data["targeted_model_or_pipeline"], list) or len(data["targeted_model_or_pipeline"]) == 0:
        return False
    if not isinstance(data["steps"], list) or len(data["steps"]) < 3:
        return False
    if not isinstance(data["manipulated_features"], list) or len(data["manipulated_features"]) == 0:
        return False
    if data["stealthiness"] not in {"low", "medium", "high"}:
        return False
    if not isinstance(data["decision_degradation_type"], str) or not data["decision_degradation_type"].strip():
        return False
    if not isinstance(data["expected_model_failure"], str) or not data["expected_model_failure"].strip():
        return False
    if not isinstance(data["detection_observed"], str) or not data["detection_observed"].strip():
        return False
    if not isinstance(data["critical_break_point"], str) or not data["critical_break_point"].strip():
        return False
    if not isinstance(data["regulatory_relevance"], list) or len(data["regulatory_relevance"]) == 0:
        return False
    if data["severity"] not in {"low", "medium", "high", "critical"}:
        return False

    if contains_bad_placeholder(data):
        return False

    frameworks = set(data["regulatory_relevance"])

    if scenario == "ai_poisoning":
        if "AI Act" not in frameworks or "DORA" not in frameworks:
            return False
        if data["stealthiness"] != "high":
            return False
    else:
        if "AI Act" not in frameworks or "DORA" not in frameworks:
            return False
        if "false negatives" not in data["decision_degradation_type"].lower() and "legitimate" not in data["decision_degradation_type"].lower():
            return False

    return True


def run_adversarial_ai(recon_output: str):
    scenario = get_scenario()
    fallback_output = build_fallback_output(scenario)

    use_fallback = os.getenv("USE_FALLBACK", "0").lower() in ("1", "true", "yes")
    if use_fallback:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    agent = build_ai_agent()

    prompt = f"""
Scenario: {scenario}

Reconnaissance output:
{recon_output}

Return ONLY one raw JSON object with exactly these keys:
- scenario_type
- scenario_name
- targeted_model_or_pipeline
- attack_vector
- steps
- manipulated_features
- stealthiness
- decision_degradation_type
- expected_model_failure
- detection_observed
- critical_break_point
- regulatory_relevance
- severity

Important:
- scenario_type must be ai_or_data_attack
- stealthiness must be low, medium, or high
- severity must be lowercase
- show how the model is manipulated without causing full system shutdown
"""

    try:
        result = agent.run(prompt)
        text = result.content if hasattr(result, "content") else str(result)

        parsed = try_parse_json(text)
        repaired = repair_ai_output(parsed, fallback_output)

        if validate_ai_output(repaired, scenario):
            return json.dumps(repaired, indent=2, ensure_ascii=False)

        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
