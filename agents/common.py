import json
import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

VALID_SCENARIOS = {
    "api_attack",
    "third_party_outage",
    "ai_poisoning",
    "input_perturbation",
}


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def to_text(result):
    if hasattr(result, "content"):
        return result.content
    return str(result)


def get_scenario() -> str:
    scenario = os.getenv("SCENARIO", "api_attack").strip()
    if scenario not in VALID_SCENARIOS:
        print(f"[WARN] Unknown SCENARIO='{scenario}'. Falling back to 'api_attack'.")
        return "api_attack"
    return scenario


def strip_markdown_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def try_parse_json(text: str):
    cleaned = strip_markdown_fences(text)
    return json.loads(cleaned)


def validate_required_keys(parsed: dict, required_keys: list[str]) -> bool:
    if not isinstance(parsed, dict):
        return False
    return all(key in parsed for key in required_keys)


def clean_final_output(data: dict):
    if not isinstance(data, dict):
        return data
    cleaned = dict(data)
    cleaned.pop("_mode", None)
    cleaned.pop("_reason", None)
    cleaned.pop("_raw_model_output", None)
    return cleaned


def map_recon_structure(parsed: dict):
    components = parsed.get("components", [])
    vendors = parsed.get("vendors", [])

    return {
        "target_systems": [c.get("name", "unknown") for c in components if isinstance(c, dict)],
        "critical_assets": components if isinstance(components, list) else [],
        "data_flows": [],
        "critical_dependencies": vendors if isinstance(vendors, list) else [],
        "entry_vectors": ["Model-generated"],
        "attack_surface_map": ["Model-generated"],
        "assumptions": ["Generated from LLM response"],
        "confidence_score": 0.7,
        "scenario_context": os.getenv("SCENARIO", "unknown"),
    }


def safe_run(agent, prompt: str, fallback_output: dict, required_keys: list[str] | None = None, agent_type: str = "generic"):
    use_fallback = os.getenv("USE_FALLBACK", "1").lower() in ("1", "true", "yes")

    if use_fallback:
        return json.dumps(clean_final_output(fallback_output), indent=2, ensure_ascii=False)

    try:
        result = agent.run(prompt)
        text = to_text(result)

        parsed = try_parse_json(text)

        if required_keys and validate_required_keys(parsed, required_keys):
            return json.dumps(clean_final_output(parsed), indent=2, ensure_ascii=False)

        if agent_type == "recon" and isinstance(parsed, dict):
            mapped = map_recon_structure(parsed)
            return json.dumps(clean_final_output(mapped), indent=2, ensure_ascii=False)

        return json.dumps(clean_final_output(fallback_output), indent=2, ensure_ascii=False)

    except Exception:
        return json.dumps(clean_final_output(fallback_output), indent=2, ensure_ascii=False)
