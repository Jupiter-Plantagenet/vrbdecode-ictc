#!/usr/bin/env bash
# reproduce_all.sh -- Reproduce all experiments from the ICTC paper.
#
# Usage:
#   bash reproduce_all.sh          # Full paper-grade runs
#   bash reproduce_all.sh --quick  # Quick sanity check (~2 min)
#
# Requirements:
#   - Python 3.12+
#   - For the GPT-2 experiment: torch, transformers, numpy
#
# All outputs are written under eval/.

set -euo pipefail

QUICK=""
if [[ "${1:-}" == "--quick" ]]; then
    QUICK="--quick"
    echo "========================================"
    echo "  QUICK MODE (reduced configurations)"
    echo "========================================"
else
    echo "========================================"
    echo "  FULL PAPER-GRADE REPRODUCTION"
    echo "========================================"
fi
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
SKIP=0

run_experiment() {
    local name="$1"
    shift
    echo ""
    echo "================================================================"
    echo "  Experiment: $name"
    echo "================================================================"
    if "$@"; then
        echo "  >> $name: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  >> $name: FAILED (exit code $?)"
        FAIL=$((FAIL + 1))
    fi
}

# -------------------------------------------------------------------
# 1. Unit tests
# -------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  Running unit tests"
echo "================================================================"
if command -v pytest &>/dev/null; then
    if pytest tests/ -v; then
        echo "  >> Unit tests: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  >> Unit tests: FAILED"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  >> pytest not installed, skipping unit tests"
    SKIP=$((SKIP + 1))
fi

# -------------------------------------------------------------------
# 2. Main detection and operational evaluation
# -------------------------------------------------------------------
run_experiment "Main detection + operational evaluation" \
    python3 eval/run_ictc.py $QUICK

# -------------------------------------------------------------------
# 3. Reviewer-evidence upgrades (attribution, authenticated root,
#    determinism, overhead, seed-grinding, CIs)
# -------------------------------------------------------------------
run_experiment "Reviewer-evidence upgrades" \
    python3 eval/run_review_upgrades.py

# -------------------------------------------------------------------
# 4. Latency scaling
# -------------------------------------------------------------------
run_experiment "Latency scaling" \
    python3 eval/run_latency_scaling.py $QUICK

# -------------------------------------------------------------------
# 5. Bias-heuristic characterization (supplementary)
# -------------------------------------------------------------------
run_experiment "Bias-heuristic characterization" \
    python3 eval/run_bias_heuristic.py $QUICK

# -------------------------------------------------------------------
# 6. Adaptive adversary analysis
# -------------------------------------------------------------------
run_experiment "Adaptive adversary" \
    python3 ref/python/adaptive_attacker.py $QUICK

# -------------------------------------------------------------------
# 7. GPT-2 validation
# -------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  Experiment: GPT-2 validation"
echo "================================================================"
if python3 -c "import torch; import transformers" 2>/dev/null; then
    if python3 eval/extract_gpt2_logits.py; then
        echo "  >> GPT-2 validation: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  >> GPT-2 validation: FAILED"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  >> torch/transformers not installed, skipping GPT-2 experiment"
    echo "  >> Install with: pip install torch transformers"
    echo "  >> Pre-computed results available in eval/gpt2_validation_results.json"
    SKIP=$((SKIP + 1))
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  REPRODUCTION SUMMARY"
echo "================================================================"
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo ""
echo "  Output files:"
echo "    eval/ictc_results.json           -- Main detection & operational results"
echo "    eval/ictc_detection.csv          -- Per-attack detection rates"
echo "    eval/ictc_operational.csv        -- Per-config latency & storage"
echo "    eval/review_upgrades_results.json -- Attribution, root, determinism, overhead"
echo "    eval/latency_scaling_results.json -- Latency scaling data"
echo "    eval/bias_heuristic_results.json  -- Bias-heuristic characterization"
echo "    eval/adaptive_adversary_results.json -- Adaptive adversary analysis"
echo "    eval/gpt2_validation_results.json -- GPT-2 logit validation"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  ** $FAIL experiment(s) FAILED **"
    exit 1
else
    echo "  All experiments completed successfully."
    exit 0
fi
