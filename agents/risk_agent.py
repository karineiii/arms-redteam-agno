import json
import os
import re
from typing import Any

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import get_scenario


def build_risk_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="RiskAgent",
        model=model,
        instructions="""
You are the Risk Agent of an agentic banking Red Team.

Your task is to assess the final business, regulatory, operational, and reputational impact
of the simulated attack path against ARMS.

Return ONLY one valid JSON object.
No markdown.
No explanations.
No extra text.

Required keys:
- global_risk_score
- risk_level
- estimated_financial_loss_eur
- regulatory_exposure_level
- financial_impact
- regulatory_impact
- reputational_impact
- operational_impact
- prioritized_vulnerabilities
- executive_summary

STRICT RULES:
- global_risk_score must be a float between 0.0 and 1.0
- risk_level must be one of: low, medium, high, critical
- estimated_financial_loss_eur must be an integer
- regulatory_exposure_level must be one of: low, medium, high, critical
- financial_impact must be one of: low, medium, high, critical
- regulatory_impact must be one of: low, medium, high, critical
- reputational_impact must be one of: low, medium, high, critical
- operational_impact must be one of: low, medium, high, critical
- prioritized_vulnerabilities must be a non-empty list
- executive_summary must be concise and concrete
- outputs must be realistic for a banking / crypto / AI compliance environment
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
            "global_risk_score": 0.86,
            "risk_level": "critical",
            "estimated_financial_loss_eur": 15000000,
            "regulatory_exposure_level": "high",
            "financial_impact": "high",
            "regulatory_impact": "high",
            "reputational_impact": "critical",
            "operational_impact": "high",
            "prioritized_vulnerabilities": [
                "Critical external API dependency not sufficiently controlled",
                "Weak transaction integrity validation",
                "Insufficient third-party assurance",
                "Weak API trust-boundary monitoring"
            ],
            "executive_summary": "ARMS presents a critical risk due to malicious transaction injection through a trusted crypto or payment interface, with major financial and regulatory exposure."
        }

    if scenario == "third_party_outage":
        return {
            "global_risk_score": 0.74,
            "risk_level": "high",
            "estimated_financial_loss_eur": 8000000,
            "regulatory_exposure_level": "high",
            "financial_impact": "medium",
            "regulatory_impact": "high",
            "reputational_impact": "high",
            "operational_impact": "critical",
            "prioritized_vulnerabilities": [
                "Overdependence on a critical external provider",
                "Insufficient resilience and failover controls",
                "Monitoring degradation during dependency outage"
            ],
            "executive_summary": "ARMS faces high operational and regulatory risk when a critical third-party dependency fails, causing monitoring degradation and reduced transaction visibility."
        }

    if scenario == "ai_poisoning":
        return {
            "global_risk_score": 0.84,
            "risk_level": "critical",
            "estimated_financial_loss_eur": 12000000,
            "regulatory_exposure_level": "high",
            "financial_impact": "high",
            "regulatory_impact": "high",
            "reputational_impact": "high",
            "operational_impact": "medium",
            "prioritized_vulnerabilities": [
                "Weak training data governance",
                "Insufficient lineage and integrity validation for model retraining",
                "Low resilience to poisoned feedback loops"
            ],
            "executive_summary": "ARMS presents a critical AI governance risk because poisoned data can silently degrade fraud detection quality while the system continues to operate."
        }

    return {
        "global_risk_score": 0.78,
        "risk_level": "high",
        "estimated_financial_loss_eur": 7000000,
        "regulatory_exposure_level": "high",
        "financial_impact": "medium",
        "regulatory_impact": "high",
        "reputational_impact": "high",
        "operational_impact": "medium",
        "prioritized_vulnerabilities": [
            "Weak inference input controls",
            "Threshold-sensitive model behavior",
            "Insufficient detection of adversarial feature manipulation"
        ],
        "executive_summary": "ARMS faces high risk from subtle input manipulation that can increase false negatives without interrupting core services."
    }


def repair_risk_output(parsed: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    repaired = {}

    allowed_levels = {"low", "medium", "high", "critical"}

    try:
        score = float(parsed.get("global_risk_score", fallback["global_risk_score"]))
    except Exception:
        score = fallback["global_risk_score"]

    if score < 0.0 or score > 1.0:
        score = fallback["global_risk_score"]
    repaired["global_risk_score"] = round(score, 2)

    risk_level = str(parsed.get("risk_level", "")).strip().lower()
    repaired["risk_level"] = risk_level if risk_level in allowed_levels else fallback["risk_level"]

    try:
        estimated_loss = int(parsed.get("estimated_financial_loss_eur", fallback["estimated_financial_loss_eur"]))
    except Exception:
        estimated_loss = fallback["estimated_financial_loss_eur"]

    if estimated_loss <= 0:
        estimated_loss = fallback["estimated_financial_loss_eur"]
    repaired["estimated_financial_loss_eur"] = estimated_loss

    regulatory_exposure = str(parsed.get("regulatory_exposure_level", "")).strip().lower()
    repaired["regulatory_exposure_level"] = (
        regulatory_exposure if regulatory_exposure in allowed_levels else fallback["regulatory_exposure_level"]
    )

    for key in ["financial_impact", "regulatory_impact", "reputational_impact", "operational_impact"]:
        value = str(parsed.get(key, "")).strip().lower()
        repaired[key] = value if value in allowed_levels else fallback[key]

    vulnerabilities = normalize_list_of_strings(parsed.get("prioritized_vulnerabilities"))
    repaired["prioritized_vulnerabilities"] = (
        vulnerabilities if vulnerabilities and not contains_bad_placeholder(vulnerabilities)
        else fallback["prioritized_vulnerabilities"]
    )

    summary = str(parsed.get("executive_summary", "")).strip()
    repaired["executive_summary"] = (
        summary if summary and not contains_bad_placeholder(summary)
        else fallback["executive_summary"]
    )

    return repaired


def validate_risk_output(data: dict[str, Any], scenario: str) -> bool:
    required_keys = [
        "global_risk_score",
        "risk_level",
        "estimated_financial_loss_eur",
        "regulatory_exposure_level",
        "financial_impact",
        "regulatory_impact",
        "reputational_impact",
        "operational_impact",
        "prioritized_vulnerabilities",
        "executive_summary",
    ]

    if not isinstance(data, dict):
        return False

    for key in required_keys:
        if key not in data:
            return False

    allowed_levels = {"low", "medium", "high", "critical"}

    try:
        score = float(data["global_risk_score"])
    except Exception:
        return False

    if score < 0.0 or score > 1.0:
        return False

    if data["risk_level"] not in allowed_levels:
        return False
    if data["regulatory_exposure_level"] not in allowed_levels:
        return False
    if data["financial_impact"] not in allowed_levels:
        return False
    if data["regulatory_impact"] not in allowed_levels:
        return False
    if data["reputational_impact"] not in allowed_levels:
        return False
    if data["operational_impact"] not in allowed_levels:
        return False

    if not isinstance(data["estimated_financial_loss_eur"], int) or data["estimated_financial_loss_eur"] <= 0:
        return False

    if not isinstance(data["prioritized_vulnerabilities"], list) or len(data["prioritized_vulnerabilities"]) < 3:
        return False

    if not isinstance(data["executive_summary"], str) or not data["executive_summary"].strip():
        return False

    if contains_bad_placeholder(data):
        return False

    if scenario == "api_attack":
        if score < 0.80:
            return False
        if data["risk_level"] != "critical":
            return False
        if data["estimated_financial_loss_eur"] < 5000000:
            return False
        if data["regulatory_exposure_level"] not in {"high", "critical"}:
            return False
        if data["financial_impact"] not in {"high", "critical"}:
            return False
        if data["regulatory_impact"] not in {"high", "critical"}:
            return False
        if data["reputational_impact"] not in {"high", "critical"}:
            return False
        if data["operational_impact"] not in {"medium", "high", "critical"}:
            return False

    elif scenario == "third_party_outage":
        if score < 0.65:
            return False
        if data["operational_impact"] not in {"high", "critical"}:
            return False

    elif scenario == "ai_poisoning":
        if score < 0.75:
            return False
        if data["regulatory_impact"] not in {"high", "critical"}:
            return False

    else:
        if score < 0.70:
            return False

    return True

def run_risk(recon_output: str, attack_output: str, ai_output: str, compliance_output: str):
    scenario = get_scenario()
    fallback_output = build_fallback_output(scenario)

    use_fallback = os.getenv("USE_FALLBACK", "0").lower() in ("1", "true", "yes")
    if use_fallback:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    agent = build_risk_agent()

    prompt = f"""
Scenario: {scenario}

Reconnaissance output:
{recon_output}

Attack output:
{attack_output}

AI attack output:
{ai_output}

Compliance output:
{compliance_output}

Return ONLY one raw JSON object with exactly these keys:
- global_risk_score
- risk_level
- estimated_financial_loss_eur
- regulatory_exposure_level
- financial_impact
- regulatory_impact
- reputational_impact
- operational_impact
- prioritized_vulnerabilities
- executive_summary

Important:
- global_risk_score must be between 0.0 and 1.0
- estimated_financial_loss_eur must be an integer
- all impact levels must be lowercase
"""

    try:
        result = agent.run(prompt)
        text = result.content if hasattr(result, "content") else str(result)

        parsed = try_parse_json(text)
        repaired = repair_risk_output(parsed, fallback_output)

        if validate_risk_output(repaired, scenario):
            return json.dumps(repaired, indent=2, ensure_ascii=False)

        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
