import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def to_text(result):
    if hasattr(result, "content"):
        return result.content
    return str(result)
