import json
from pathlib import Path

from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.adversarial_ai_agent import run_adversarial_ai
from agents.compliance_agent import run_compliance
from agents.risk_agent import run_risk


def main():
    recon = run_recon()
    attack = run_attack(recon)
    ai_attack = run_adversarial_ai(recon)
    compliance = run_compliance(recon, attack, ai_attack)
    risk = run_risk(recon, attack, ai_attack, compliance)

    final_report = {
        "recon": recon,
        "attack": attack,
        "adversarial_ai": ai_attack,
        "compliance": compliance,
        "risk": risk
    }

    Path("outputs").mkdir(exist_ok=True)
    Path("outputs/final_report.json").write_text(
        json.dumps(final_report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(json.dumps(final_report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
