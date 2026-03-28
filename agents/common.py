import json
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def to_text(result):
    if hasattr(result, "content"):
        return result.content
    return str(result)


def safe_run(agent, prompt: str, fallback_output: dict):
    use_fallback = os.getenv("USE_FALLBACK", "1").lower() in ("1", "true", "yes")

    if use_fallback:
        fallback_output["_mode"] = "forced_fallback"
        fallback_output["_reason"] = "API disabled or quota unavailable"
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)

    try:
        result = agent.run(prompt)
        text = to_text(result)

        if "insufficient_quota" in text or "exceeded your current quota" in text.lower():
            fallback_output["_mode"] = "fallback_after_api_error"
            fallback_output["_reason"] = text
            return json.dumps(fallback_output, indent=2, ensure_ascii=False)

        return text
    except Exception as e:
        fallback_output["_mode"] = "fallback_after_exception"
        fallback_output["_reason"] = str(e)
        return json.dumps(fallback_output, indent=2, ensure_ascii=False)
