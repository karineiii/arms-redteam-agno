import json
from pathlib import Path
from rich import print
from rich.panel import Panel

from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.adversarial_ai_agent import run_adversarial_ai
from agents.compliance_agent import run_compliance
from agents.risk_agent import run_risk


def parse(x):
    try:
        return json.loads(x)
    except:
        return x


def print_section(title, data):
    print(Panel.fit(
        json.dumps(data, indent=2, ensure_ascii=False),
        title=title,
        border_style="cyan"
    ))

def main():
    recon = parse(run_recon())
    attack = parse(run_attack(json.dumps(recon)))
    ai_attack = parse(run_adversarial_ai(json.dumps(recon)))
    compliance = parse(run_compliance(json.dumps(recon), json.dumps(attack), json.dumps(ai_attack)))
    risk = parse(run_risk(json.dumps(recon), json.dumps(attack), json.dumps(ai_attack), json.dumps(compliance)))

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

    # 🔥 affichage lisible
    print_section("RECONNAISSANCE", recon)
    print_section("ATTACK SCENARIO", attack)
    print_section("AI ATTACK", ai_attack)
    print_section("COMPLIANCE GAPS", compliance)
    print_section("RISK ASSESSMENT", risk)


if __name__ == "__main__":
    main()
