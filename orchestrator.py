import json
from pathlib import Path

from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.adversarial_ai_agent import run_adversarial_ai
from agents.compliance_agent import run_compliance
from agents.risk_agent import run_risk


def maybe_parse_json(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def main():
    recon = maybe_parse_json(run_recon())
    attack = maybe_parse_json(run_attack(json.dumps(recon, ensure_ascii=False)))
    ai_attack = maybe_parse_json(run_adversarial_ai(json.dumps(recon, ensure_ascii=False)))
    compliance = maybe_parse_json(
        run_compliance(
            json.dumps(recon, ensure_ascii=False),
            json.dumps(attack, ensure_ascii=False),
            json.dumps(ai_attack, ensure_ascii=False),
        )
    )
    risk = maybe_parse_json(
        run_risk(
            json.dumps(recon, ensure_ascii=False),
            json.dumps(attack, ensure_ascii=False),
            json.dumps(ai_attack, ensure_ascii=False),
            json.dumps(compliance, ensure_ascii=False),
        )
    )

    final_report = {
        "recon_agent_output": recon,
        "attack_agent_output": attack,
        "adversarial_ai_agent_output": ai_attack,
        "compliance_breaker_output": compliance,
        "impact_risk_scoring_output": risk
    }

    Path("outputs").mkdir(exist_ok=True)
    Path("outputs/final_report.json").write_text(
        json.dumps(final_report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(json.dumps(final_report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
