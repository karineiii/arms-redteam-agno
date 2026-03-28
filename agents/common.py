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
    for key in required_keys:
        if key not in parsed:
            return False
    return True


def safe_run(agent, prompt: str, fallback_output: dict, required_keys: list[str] | None = None):
    use_fallback = os.getenv("USE_FALLBACK", "1").lower() in ("1", "true", "yes")

    if use_fallback:
        fallback_output["_mode"] = "forced_fallback"
        fallback_output["_reason"] = "API disabled or fallback forced"
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    try:
        result = agent.run(prompt)
        text = to_text(result)

        if "insufficient_quota" in text.lower():
            fallback_output["_mode"] = "fallback_after_api_error"
            fallback_output["_reason"] = text
            return json.dumps(fallback_output, indent=2, ensure_ascii=False)

        try:
            parsed = try_parse_json(text)

            if required_keys and not validate_required_keys(parsed, required_keys):
                try:
                    mapped = {
                        "target_systems": parsed.get("components", []),
                        "critical_assets": parsed.get("components", []),
                        "data_flows": [],
                        "critical_dependencies": parsed.get("vendors", []),
                        "entry_vectors": ["Model-generated"],
                        "attack_surface_map": ["Model-generated"],
                        "assumptions": ["Generated from LLM response"],
                        "confidence_score": 0.7,
                        "scenario_context": os.getenv("SCENARIO", "unknown"),
                    }

                    return json.dumps(mapped, indent=2, ensure_ascii=False)

                except Exception:
                    fallback_output["_mode"] = "fallback_after_invalid_structure"
                    fallback_output["_reason"] = f"Model JSON missing required keys: {required_keys}"
                    fallback_output["_raw_model_output"] = parsed
                    return json.dumps(fallback_output, indent=2, ensure_ascii=False)

            return json.dumps(parsed, indent=2, ensure_ascii=False)

        except Exception:
            fallback_output["_mode"] = "fallback_after_invalid_json"
            fallback_output["_reason"] = "Model returned non-compliant JSON"
            fallback_output["_raw_model_output"] = text
            return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    except Exception as e:
        fallback_output["_mode"] = "fallback_after_exception"
        fallback_output["_reason"] = str(e)
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
