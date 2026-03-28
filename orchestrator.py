import json
from pathlib import Path

from rich import print
from rich.panel import Panel

from agents.recon_agent import run_recon
from agents.attack_agent import run_attack
from agents.adversarial_ai_agent import run_adversarial_ai
from agents.compliance_agent import run_compliance
from agents.risk_agent import run_risk
from agents.common import get_scenario


def parse(x):
    try:
        return json.loads(x)
    except Exception:
        return x


def print_section(title, data):
    print(Panel.fit(
        json.dumps(data, indent=2, ensure_ascii=False),
        title=title,
        border_style="cyan"
    ))


def build_summary(scenario, recon, attack, ai_attack, compliance, risk):
    return {
        "scenario": scenario,
        "target": recon.get("target_systems", []),
        "conventional_attack": attack.get("scenario_name"),
        "ai_attack": ai_attack.get("scenario_name"),
        "break_points": [
            attack.get("critical_break_point"),
            ai_attack.get("critical_break_point")
        ],
        "top_regulatory_gaps": [
            gap.get("framework") + ": " + gap.get("gap")
            for gap in compliance.get("identified_gaps", [])
        ],
        "risk_score": risk.get("global_risk_score"),
        "risk_level": risk.get("risk_level"),
        "top_recommendations": compliance.get("recommended_controls", [])[:3]
    }


def main():
    scenario = get_scenario()

    recon = parse(run_recon())
    attack = parse(run_attack(json.dumps(recon, ensure_ascii=False)))
    ai_attack = parse(run_adversarial_ai(json.dumps(recon, ensure_ascii=False)))
    compliance = parse(
        run_compliance(
            json.dumps(recon, ensure_ascii=False),
            json.dumps(attack, ensure_ascii=False),
            json.dumps(ai_attack, ensure_ascii=False),
        )
    )
    risk = parse(
        run_risk(
            json.dumps(recon, ensure_ascii=False),
            json.dumps(attack, ensure_ascii=False),
            json.dumps(ai_attack, ensure_ascii=False),
            json.dumps(compliance, ensure_ascii=False),
        )
    )

    summary = build_summary(scenario, recon, attack, ai_attack, compliance, risk)

    final_report = {
        "summary": summary,
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

    print_section("SUMMARY", summary)
    print_section("RECONNAISSANCE", recon)
    print_section("ATTACK SCENARIO", attack)
    print_section("AI ATTACK", ai_attack)
    print_section("COMPLIANCE GAPS", compliance)
    print_section("RISK ASSESSMENT", risk)


if __name__ == "__main__":
    main()
