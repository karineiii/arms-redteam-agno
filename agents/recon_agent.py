import json
from pathlib import Path


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_recon():
    architecture = load_json("data/architecture_arms.json")
    vendors = load_json("data/vendors.json")

    return {
        "assets": architecture["components"],
        "critical_dependencies": vendors["vendors"],
        "entry_points": [
            {"name": "API Gateway", "risk": "high"},
            {"name": "Crypto API Connector", "risk": "high"},
            {"name": "Case Management Console", "risk": "medium"}
        ],
        "data_flows": [
            {"source": "API Gateway", "target": "Transaction Ingestion Pipeline"},
            {"source": "Transaction Ingestion Pipeline", "target": "Fraud Detection Model"},
            {"source": "Fraud Detection Model", "target": "AML Monitoring Engine"}
        ],
        "attack_surface_map": [
            "External API exposure",
            "Third-party crypto API dependency",
            "IAM misconfiguration risk",
            "Logging and observability concentration risk"
        ],
        "assumptions": [
            "ARMS depends on third-party APIs",
            "Fraud detection relies on ML inputs",
            "Critical services are cloud-hosted"
        ],
        "confidence_score": 0.84
    }
