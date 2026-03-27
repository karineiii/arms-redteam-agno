def run_attack(recon_output):
    return {
        "scenario_name": "Compromise of payment or crypto API",
        "attack_path": [
            "Enumerate exposed API entry points",
            "Abuse weak validation on third-party connector",
            "Inject plausible but malicious transaction patterns",
            "Influence AML or fraud monitoring decisions"
        ],
        "target_assets": [
            "API Gateway",
            "Crypto API Connector",
            "Transaction Ingestion Pipeline"
        ],
        "exploited_weaknesses": [
            "Weak request validation",
            "Overtrust in third-party API data",
            "Insufficient transaction integrity checks"
        ],
        "observable_signals": [
            "Abnormal transaction bursts",
            "Inconsistent payload fields",
            "Unexpected partner-side request patterns"
        ],
        "system_reaction": "Potential false negatives in fraud monitoring",
        "break_point": "Insufficient integrity control on incoming third-party transactions"
    }
