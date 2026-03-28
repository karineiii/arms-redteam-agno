cat > README.md <<'EOF'
# ARMS Red Team - Multi-Agent Architecture

Academic project: design of a 5-agent Red Team to assess the resilience of the ARMS (Agentic Risk Monitoring System) before production deployment.

## Objective
This project simulates realistic attacks against ARMS in order to:
- test system resilience,
- identify hidden regulatory vulnerabilities,
- evaluate cyber, data and AI attack paths,
- translate technical findings into compliance gaps,
- quantify business and regulatory impact.

## 5 Agents
1. **Reconnaissance Agent**  
   Maps critical assets, data flows, dependencies and entry points.

2. **Attack Agent**  
   Simulates a conventional cyber attack with high probability.

3. **Adversarial AI Agent**  
   Simulates an attack against the AI/data pipeline.

4. **Compliance Breaker Agent**  
   Maps findings to DORA, MiCA, AI Act and GDPR gaps.

5. **Impact & Risk Scoring Agent**  
   Produces a global risk score and prioritizes findings.

## Interactions
- Reconnaissance feeds Attack Agent and Adversarial AI Agent
- Their outputs are consolidated by Compliance Breaker
- Impact & Risk Scoring aggregates all results into a final risk view

## Scenarios
### Scenario 1 - Conventional cyber attack
Compromise of a payment or crypto API through weak validation and overtrust in third-party data, leading to malicious but plausible transaction injection.

### Scenario 2 - AI/data attack
Progressive poisoning of the AI feedback or retraining pipeline, causing fraudulent patterns to be learned as legitimate without stopping the system.

## Main Findings
- Critical third-party API dependency
- Weak transaction integrity controls
- AI pipeline vulnerable to poisoning
- Insufficient traceability and explainability
- Significant regulatory exposure

## Risk Score
**Global risk score: 0.82 / 1.00 (Critical)**

## Run
```bash
python3 app.py
