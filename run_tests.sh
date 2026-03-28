#!/usr/bin/env bash
set -e

export USE_FALLBACK=1

for scenario in api_attack third_party_outage ai_poisoning input_perturbation
do
  echo ""
  echo "========================================"
  echo "Running scenario: $scenario"
  echo "========================================"
  export SCENARIO=$scenario
  python3 app.py > /tmp/arms_${scenario}.log
  cp outputs/final_report.json outputs/final_report_${scenario}.json
  echo "Saved: outputs/final_report_${scenario}.json"
done
