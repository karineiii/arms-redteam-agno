import json
import os
import re
from typing import Any

from agno.agent import Agent
from agno.models.openai import OpenAIChat

from agents.common import get_scenario


def build_compliance_agent():
    model = OpenAIChat(
        id="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

    return Agent(
        name="ComplianceAgent",
        model=model,
        instructions="""
You are the Compliance Agent of an agentic banking Red Team.

Your task is to identify concrete regulatory and governance gaps caused by the simulated attack path against ARMS.

Return ONLY one valid JSON object.
No markdown.
No explanations.
No extra text.

Required keys:
- identified_gaps
- arms_failure_points
- why_non_compliant
- recommended_controls
- traceability_findings
- auditability_findings
- data_governance_findings

STRICT RULES:
- identified_gaps must be a non-empty list of objects
- each identified_gaps item must contain:
  framework, gap, evidence, severity, control_missing, expected_control
- framework must be one of: DORA, MiCA, AI Act, GDPR
- severity must be one of: low, medium, high, critical
- arms_failure_points must be a non-empty list
- why_non_compliant must be a non-empty list
- recommended_controls must be a non-empty list
- traceability_findings must be a non-empty list
- auditability_findings must be a non-empty list
- data_governance_findings must be a non-empty list
- outputs must be realistic for banking / crypto / AI compliance
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
            "identified_gaps": [
                {
                    "framework": "DORA",
                    "gap": "Critical third-party dependency insufficiently controlled",
                    "evidence": "Crypto API connector is trusted without strong integrity assurance for incoming transaction data.",
                    "severity": "high",
                    "control_missing": "Strong integrity validation and third-party assurance over external transaction inputs",
                    "expected_control": "Signed data flows, supplier assurance checks, dependency risk controls, and continuous monitoring of trust boundaries"
                },
                {
                    "framework": "MiCA",
                    "gap": "Crypto-related operations insufficiently secured",
                    "evidence": "Manipulated crypto transaction flows can affect fraud and AML monitoring outcomes.",
                    "severity": "high",
                    "control_missing": "Stronger protection of crypto transaction ingestion and monitoring flows",
                    "expected_control": "End-to-end verification of crypto transaction data, secure API controls, and stronger monitoring of suspicious crypto activity"
                }
            ],
            "arms_failure_points": [
                "Weak validation of third-party transaction data",
                "Insufficient monitoring of API trust boundaries",
                "Dependence on external crypto data without strong integrity verification"
            ],
            "why_non_compliant": [
                "Critical ICT dependencies are insufficiently controlled",
                "Crypto-related monitoring can be influenced by manipulated external data",
                "Controls are not strong enough to ensure resilient and trustworthy monitoring"
            ],
            "recommended_controls": [
                "Strengthen API validation and integrity controls",
                "Add third-party assurance and transaction signing checks",
                "Implement stronger trust-boundary monitoring for external dependencies",
                "Introduce anomaly detection for manipulated transaction payloads"
            ],
            "traceability_findings": [
                "Traceability of external transaction data sources is incomplete across the ingestion chain",
                "Linking suspicious decisions back to original third-party payloads is not consistently guaranteed"
            ],
            "auditability_findings": [
                "Audit evidence is weakened when external transaction integrity cannot be fully demonstrated",
                "Post-incident reconstruction of decision paths may be incomplete for manipulated API payloads"
            ],
            "data_governance_findings": [
                "External transaction data quality and provenance controls are insufficient",
                "Data integrity checks are not strong enough before fraud and AML scoring"
            ]
        }

    if scenario == "third_party_outage":
        return {
            "identified_gaps": [
                {
                    "framework": "DORA",
                    "gap": "Operational resilience overly dependent on a critical external provider",
                    "evidence": "A third-party outage significantly degrades monitoring visibility and response capability.",
                    "severity": "high",
                    "control_missing": "Resilience, failover, and dependency continuity controls",
                    "expected_control": "Tested failover mechanisms, contingency plans, and dependency resilience monitoring"
                },
                {
                    "framework": "MiCA",
                    "gap": "Crypto transaction oversight becomes unreliable during provider disruption",
                    "evidence": "Loss of external crypto feed reduces visibility on crypto-related operations.",
                    "severity": "medium",
                    "control_missing": "Fallback visibility and continuity controls for crypto monitoring",
                    "expected_control": "Alternative data sources, service continuity design, and resilient crypto monitoring workflows"
                }
            ],
            "arms_failure_points": [
                "Overdependence on a critical external provider",
                "Insufficient resilience and failover controls",
                "Monitoring degradation during dependency outage"
            ],
            "why_non_compliant": [
                "Resilience obligations are weakened by poor dependency continuity planning",
                "Crypto monitoring becomes unreliable during provider failure"
            ],
            "recommended_controls": [
                "Implement tested failover and degraded-mode procedures",
                "Add redundancy for critical external feeds",
                "Strengthen continuity monitoring for third-party services"
            ],
            "traceability_findings": [
                "Transaction trace continuity is weakened during provider outage",
                "Source visibility gaps make event reconstruction harder"
            ],
            "auditability_findings": [
                "Audit records may be incomplete when external feeds are unavailable",
                "Evidence of monitoring continuity is insufficient"
            ],
            "data_governance_findings": [
                "Dependency outage handling is not sufficiently integrated into data governance",
                "Fallback data quality controls are limited"
            ]
        }

    if scenario == "ai_poisoning":
        return {
            "identified_gaps": [
                {
                    "framework": "AI Act",
                    "gap": "Model governance is insufficient to prevent or detect poisoned retraining inputs",
                    "evidence": "Poisoned labels or feedback can silently degrade fraud detection behavior over time.",
                    "severity": "high",
                    "control_missing": "Training data lineage, validation, and poisoning detection controls",
                    "expected_control": "Documented model governance, validated retraining inputs, lineage tracking, and ongoing quality controls"
                },
                {
                    "framework": "GDPR",
                    "gap": "Decision quality and fairness may degrade without adequate governance safeguards",
                    "evidence": "Biased retraining can negatively affect individuals through inaccurate model decisions.",
                    "severity": "medium",
                    "control_missing": "Governance controls ensuring fair, accurate, and reviewable automated outcomes",
                    "expected_control": "Stronger reviewability, fairness monitoring, and data governance over model inputs"
                },
                {
                    "framework": "DORA",
                    "gap": "Operational controls are too weak to prevent integrity degradation in a critical AI pipeline",
                    "evidence": "Untrusted feedback data can compromise model performance without immediate interruption of service.",
                    "severity": "high",
                    "control_missing": "Integrity controls over retraining and feedback pipelines",
                    "expected_control": "Controlled retraining workflows, monitored feedback ingestion, and integrity validation for model lifecycle operations"
                }
            ],
            "arms_failure_points": [
                "Weak training data governance",
                "Insufficient lineage and integrity validation for retraining inputs",
                "Low resilience to poisoned feedback loops"
            ],
            "why_non_compliant": [
                "Model governance does not sufficiently prevent silent quality degradation",
                "Automated outcomes may become less reliable and less defensible",
                "Operational controls on the AI lifecycle are insufficient"
            ],
            "recommended_controls": [
                "Implement training data lineage and integrity validation",
                "Add poisoning detection before retraining",
                "Introduce stronger approval gates for model updates",
                "Monitor fairness and drift after retraining"
            ],
            "traceability_findings": [
                "Traceability between model decisions and retraining data sources is incomplete",
                "It may be difficult to identify which poisoned inputs influenced degraded outputs"
            ],
            "auditability_findings": [
                "Audit trails for model updates and feedback ingestion are insufficiently granular",
                "Evidence supporting model change governance is incomplete"
            ],
            "data_governance_findings": [
                "Retraining data governance is too weak for a high-impact fraud detection model",
                "Integrity and provenance controls over labeled feedback are insufficient"
            ]
        }

    return {
        "identified_gaps": [
            {
                "framework": "AI Act",
                "gap": "Inference-time protections are insufficient against adversarial feature manipulation",
                "evidence": "Small input changes can lead to incorrect model outcomes without interrupting service.",
                "severity": "high",
                "control_missing": "Robust inference validation and adversarial resilience controls",
                "expected_control": "Feature validation, adversarial monitoring, and stronger safeguards around model inference"
            },
            {
                "framework": "DORA",
                "gap": "Operational controls do not sufficiently detect integrity issues at inference time",
                "evidence": "Manipulated features can affect monitoring quality without immediate operational detection.",
                "severity": "medium",
                "control_missing": "Integrity controls around critical inference inputs",
                "expected_control": "Monitoring of anomalous inference inputs, stronger validation, and resilience checks"
            }
        ],
        "arms_failure_points": [
            "Weak inference input controls",
            "Threshold-sensitive model behavior",
            "Insufficient detection of adversarial feature manipulation"
        ],
        "why_non_compliant": [
            "Inference-time integrity is not sufficiently protected",
            "Operational monitoring is too weak to detect subtle manipulation"
        ],
        "recommended_controls": [
            "Strengthen feature validation before scoring",
            "Add inference-time anomaly detection",
            "Monitor model robustness against adversarial inputs"
        ],
        "traceability_findings": [
            "Traceability of manipulated input features is limited at inference time",
            "Reconstructing how subtle input changes influenced decisions may be difficult"
        ],
        "auditability_findings": [
            "Audit records may not fully capture feature-level manipulation attempts",
            "Decision reconstruction is weakened when inference controls are insufficient"
        ],
        "data_governance_findings": [
            "Inference input governance is too weak for a sensitive fraud detection workflow",
            "Feature validation controls are not sufficient before model scoring"
        ]
    }


def normalize_gap_item(item: Any) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None

    framework = str(item.get("framework", "")).strip()
    gap = str(item.get("gap", "")).strip()
    evidence = str(item.get("evidence", "")).strip()
    severity = str(item.get("severity", "")).strip().lower()
    control_missing = str(item.get("control_missing", "")).strip()
    expected_control = str(item.get("expected_control", "")).strip()

    allowed_frameworks = {"DORA", "MiCA", "AI Act", "GDPR"}
    allowed_severity = {"low", "medium", "high", "critical"}

    if framework not in allowed_frameworks:
        return None
    if severity not in allowed_severity:
        return None
    if not gap or not evidence or not control_missing or not expected_control:
        return None

    candidate = {
        "framework": framework,
        "gap": gap,
        "evidence": evidence,
        "severity": severity,
        "control_missing": control_missing,
        "expected_control": expected_control,
    }

    if contains_bad_placeholder(candidate):
        return None

    return candidate


def repair_compliance_output(parsed: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    repaired = {}

    identified_gaps = parsed.get("identified_gaps")
    normalized_gaps = []
    if isinstance(identified_gaps, list):
        for item in identified_gaps:
            norm = normalize_gap_item(item)
            if norm:
                normalized_gaps.append(norm)

    repaired["identified_gaps"] = normalized_gaps if normalized_gaps else fallback["identified_gaps"]

    for key in [
        "arms_failure_points",
        "why_non_compliant",
        "recommended_controls",
        "traceability_findings",
        "auditability_findings",
        "data_governance_findings",
    ]:
        value = normalize_list_of_strings(parsed.get(key))
        repaired[key] = value if value and not contains_bad_placeholder(value) else fallback[key]

    return repaired


def validate_compliance_output(data: dict[str, Any], scenario: str) -> bool:
    required_keys = [
        "identified_gaps",
        "arms_failure_points",
        "why_non_compliant",
        "recommended_controls",
        "traceability_findings",
        "auditability_findings",
        "data_governance_findings",
    ]

    if not isinstance(data, dict):
        return False

    for key in required_keys:
        if key not in data:
            return False

    if not isinstance(data["identified_gaps"], list) or len(data["identified_gaps"]) < 2:
        return False

    for item in data["identified_gaps"]:
        if normalize_gap_item(item) is None:
            return False

    for key in [
        "arms_failure_points",
        "why_non_compliant",
        "recommended_controls",
        "traceability_findings",
        "auditability_findings",
        "data_governance_findings",
    ]:
        if not isinstance(data[key], list) or len(data[key]) == 0:
            return False

    if contains_bad_placeholder(data):
        return False

    frameworks = {item["framework"] for item in data["identified_gaps"]}

    if scenario == "api_attack":
        if "DORA" not in frameworks or "MiCA" not in frameworks:
            return False
    elif scenario == "third_party_outage":
        if "DORA" not in frameworks or "MiCA" not in frameworks:
            return False
    elif scenario == "ai_poisoning":
        if "AI Act" not in frameworks or "DORA" not in frameworks:
            return False
    else:
        if "AI Act" not in frameworks or "DORA" not in frameworks:
            return False

    return True


def run_compliance(recon_output: str, attack_output: str, ai_output: str):
    scenario = get_scenario()
    fallback_output = build_fallback_output(scenario)

    use_fallback = os.getenv("USE_FALLBACK", "0").lower() in ("1", "true", "yes")
    if use_fallback:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    agent = build_compliance_agent()

    prompt = f"""
Scenario: {scenario}

Reconnaissance output:
{recon_output}

Attack output:
{attack_output}

AI attack output:
{ai_output}

Return ONLY one raw JSON object with exactly these keys:
- identified_gaps
- arms_failure_points
- why_non_compliant
- recommended_controls
- traceability_findings
- auditability_findings
- data_governance_findings

Important:
- identified_gaps must contain objects with:
  framework, gap, evidence, severity, control_missing, expected_control
- framework must be one of: DORA, MiCA, AI Act, GDPR
- severity must be lowercase
"""

    try:
        result = agent.run(prompt)
        text = result.content if hasattr(result, "content") else str(result)

        parsed = try_parse_json(text)
        repaired = repair_compliance_output(parsed, fallback_output)

        if validate_compliance_output(repaired, scenario):
            return json.dumps(repaired, indent=2, ensure_ascii=False)

        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
