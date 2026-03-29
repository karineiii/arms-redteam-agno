#  ARMS Red Team - Multi-Agent Architecture

Academic project focused on the design and implementation of a **5-agent Red Team system** to assess the resilience of the **ARMS (Agentic Risk Monitoring System)** before production deployment.

---

#  Objective

This project simulates realistic cyber and AI attack scenarios against ARMS in order to:

- Evaluate system resilience under adversarial conditions  
- Identify hidden technical and regulatory vulnerabilities  
- Explore cyber, data, and AI attack paths  
- Translate technical weaknesses into compliance gaps  
- Quantify business, financial, and regulatory impact  

---

#  Multi-Agent Architecture

The system is composed of **5 specialized agents**, each responsible for a specific phase of the Red Team analysis:

## 1. Reconnaissance Agent
- Maps critical assets, data flows, and system dependencies  
- Identifies entry points and attack surface  
- Builds a structured system overview  

## 2. Attack Agent
- Simulates a **realistic conventional cyber attack**  
- Targets APIs, transaction pipelines, and third-party dependencies  
- Defines attacker objectives, preconditions, and execution steps  

## 3. Adversarial AI Agent
- Simulates **AI and data-centric attacks**  
- Targets model inference and training pipelines  
- Produces **stealthy degradation scenarios** without system interruption  

## 4. Compliance Breaker Agent
- Maps vulnerabilities to regulatory frameworks:
  - DORA  
  - MiCA  
  - AI Act  
  - GDPR  
- Identifies missing controls and compliance failures  

## 5. Impact & Risk Scoring Agent
- Aggregates all findings  
- Produces a **global risk score**  
- Estimates:
  - Financial impact  
  - Regulatory exposure  
  - Reputational damage  
- Prioritizes vulnerabilities and generates an executive summary  

---

#  Agent Interactions

- Recon feeds both Attack and AI agents  
- Attack and AI outputs are consolidated by Compliance  
- Risk Agent aggregates everything into a final decision layer  

---

#  Scenarios

## Scenario 1 — Conventional Cyber Attack

Compromise of a payment or crypto API through:

- Weak input validation  
- Overtrust in third-party data  
- Lack of integrity verification  

Result: Injection of malicious but plausible transactions affecting fraud and AML monitoring  

---

## Scenario 2 — AI / Data Attack

Progressive poisoning or manipulation of the AI pipeline:

- Corruption of feedback or retraining data  
- Subtle manipulation of model inputs  

 Result: The system remains operational but produces degraded or biased decisions  

---

#  Key Findings

- Critical dependency on external crypto/API providers  
- Weak transaction integrity validation  
- Vulnerability of AI pipeline to poisoning and manipulation  
- Insufficient traceability and auditability  
- Significant regulatory exposure across DORA, MiCA, AI Act, and GDPR  

---

#  Risk Assessment

**Global Risk Score: 0.82 – 0.86 / 1.00 (Critical)**  

Key impacts identified:

- High financial exposure (potential multi-million loss)  
- High regulatory risk (non-compliance across multiple frameworks)  
- Critical reputational impact  
- Significant operational vulnerability  

---

#  Execution

Run the system locally:
```bash
python3 app.py
```
Example .env file:  
```bash
GROQ_API_KEY=the_key
SCENARIO=api_attack
USE_FALLBACK=0
```
To run without API usage:
```bash
USE_FALLBACK=1
```
