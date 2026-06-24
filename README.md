# Attack-Aware Forensic Receipts for Accountable Large Language Model Decoding Services

**Authors:** George Chidera Akor, Love Allen Chijioke Ahakonye, Jae Min Lee, Dong-Seong Kim

**Affiliation:** IT Convergence Engineering and NSLab Co. Ltd., Kumoh National Institute of Technology, Gumi, South Korea; ICT Convergence Research Center, Kumoh National Institute of Technology

**Venue:** ICTC 2026

## Description

This repository provides the source code and evaluation scripts for the ICTC 2026 paper "Attack-Aware Forensic Receipts for Accountable Large Language Model Decoding Services." The paper presents a forensic audit architecture for LLM decoding services that binds policy commitments, per-step receipts, tamper-evident chaining under an **authenticated chain root**, and deterministic re-execution into chain-of-custody evidence artifacts.

Deterministic re-execution detects every output-changing policy or randomness manipulation and all transcript-integrity attacks, with soundness reducing to hash collision-resistance and pseudorandom-function (PRF) security. Each failure maps to its own reason code, giving 100% per-class attribution. Candidate-list manipulation is detected against a ground-truth shortlist or, lacking one, against the authenticated root: a relay/store that edits the shortlist after generation and re-chains produces a root that diverges from the authenticated one, so downstream tampering is caught **without** ground truth. The one residual gap is a malicious receipt generator that fabricates a self-consistent shortlist and root at source, which the paper closes with client co-signing, an attested enclave, or a verifiable-forward-pass anchor. A provider that controls the seed can grind it to bias an output (a stated limitation), motivating VRF/beacon-supplied randomness.

On a SHA-256 prototype the scheme attains 0.0% false positives (0/10,000 honest transcripts), sub-millisecond per-step latency (0.021–0.067 ms/step) and generation overhead, compact evidence artifacts (8–307 KB), and bit-identical receipt roots across independent processes. A three-baseline comparison (Merkle log signing, policy-commitment verification, watermark detection) shows re-execution is necessary for semantic attack detection (5/5 vs. 2/5 for the strongest alternative).

## Repository Structure

```
ref/python/              Core implementation
  decoding_ref.py          Fixed-point decoding step (DecodeStep)
  receipt.py               Receipt generation, chaining, authenticated root
  forensic_verifier.py     Verification with per-class reason codes
  attack_simulator.py      Attack implementations (four classes)
  adaptive_attacker.py     Adaptive adversary with evasion search
  baseline_merkle.py       Baseline 1: Merkle log signing
  baseline_policy_commit.py Baseline 2: Policy-commitment verifier
  baseline_watermark.py    Baseline 3: Kirchenbauer-style watermark detector
  security_analysis.py     Constructive security proofs

eval/                    Evaluation scripts and pre-computed results
  run_ictc.py              Main detection + operational evaluation
  run_review_upgrades.py   Attribution, authenticated-root ablation,
                           determinism, inline overhead, seed-grinding,
                           and Wilson-CI experiments
  run_latency_scaling.py   Latency scaling vs. (K, N)
  run_bias_heuristic.py    Supplementary bias-heuristic characterization
  extract_gpt2_logits.py   GPT-2 logit validation
  *.json, *.csv            Pre-computed results

tests/                   Unit tests
  test_forensic_verifier.py   Verification pipeline tests
  test_baseline_comparison.py Baseline comparison and security-proof tests
```

The paper source (LaTeX) is maintained separately; this repository is the code artifact and is referenced from the paper.

## Requirements

- **Python 3.12+** (the core pipeline and verifier use only the standard library)
- **pytest** (for unit tests)
- **torch + transformers + numpy** (only for the GPT-2 validation experiment)

### Install

```bash
# Minimal (core experiments only -- no external packages needed)
pip install pytest

# Full (including the GPT-2 validation experiment)
pip install -r requirements.txt
```

## Reproducing Results

### Quick sanity check (~2 minutes)

```bash
bash reproduce_all.sh --quick
```

### Full reproduction (~30 minutes without GPT-2, ~60 minutes with)

```bash
bash reproduce_all.sh
```

### Individual experiments

#### 1. Unit tests

```bash
pytest tests/ -v
```

Verifies correct detection of all attack classes, baseline limitations (Merkle and policy-commit each miss the non-structural classes), and the constructive security proofs.

#### 2. Main detection and operational evaluation

```bash
python3 eval/run_ictc.py           # Full: K in {16,32,64}, N in {32,64,128}
python3 eval/run_ictc.py --quick   # Quick: K=16, N in {16,32}
```

**Output:** `eval/ictc_results.json`, `eval/ictc_detection.csv`, `eval/ictc_operational.csv`

**Expected:** 100% detection when a tampered step is present; 0.0% false positives (0/10,000; 95% Wilson CI [0.0, 0.038]%); baseline comparison Forensic 5/5, Policy-Commit 2/5, Merkle 2/5, Watermark 0/5; per-step latency 0.021–0.067 ms; evidence size 8–307 KB.

#### 3. Reviewer-evidence upgrades

```bash
python3 eval/run_review_upgrades.py
```

**Output:** `eval/review_upgrades_results.json`

**Expected:** per-class reason-code attribution 100% (5 classes × 100); downstream candidate tampering detected 100/100 against the authenticated root with no ground truth (vs. 13/100 by per-step checks alone); receipt root bit-identical across independent processes; inline receipt-generation overhead ≈0.04 ms/step; seed grinding under provider-chosen σ forces a target in a few tries and verifies clean (limitation); Wilson CIs for the headline counts.

#### 4. Latency scaling

```bash
python3 eval/run_latency_scaling.py           # Full: 15 (K,N) configs, 100 runs each
python3 eval/run_latency_scaling.py --quick   # Quick: 6 configs, 30 runs each
```

**Output:** `eval/latency_scaling_results.json` — linear scaling in N, per-step latency 0.021–0.067 ms/step.

#### 5. Adaptive adversary

```bash
python3 ref/python/adaptive_attacker.py           # Full run
python3 ref/python/adaptive_attacker.py --quick   # Quick run
```

**Output:** `eval/adaptive_adversary_results.json` — 0% output-changing evasion at all entropy levels. Degenerate-case evasion (identical output despite a different policy) is harmless: there is nothing to detect because the output is correct.

#### 6. Bias-heuristic characterization (supplementary)

```bash
python3 eval/run_bias_heuristic.py           # Full: 1000 FP transcripts, 200 per bias level
python3 eval/run_bias_heuristic.py --quick   # Quick: 100 FP, 50 per level
```

**Output:** `eval/bias_heuristic_results.json` — 0.0% false-positive rate on honest transcripts; the PRF check catches bias injection at all levels.

#### 7. GPT-2 validation

Requires `torch` and `transformers`:

```bash
pip install torch transformers
python3 eval/extract_gpt2_logits.py
```

**Output:** `eval/gpt2_validation_results.json` — all 100 honest transcripts pass; 100% detection for all attack types with ground-truth shortlists (53% for candidate manipulation without ground truth, marking the trust boundary); sub-millisecond per-step verification on real GPT-2 logits.

## Pre-Computed Results

All result files are included in `eval/` so readers can inspect the data without re-running experiments. The `--quick` flag on each script produces directionally identical results with smaller sample sizes for fast verification.

## License

MIT License

Copyright (c) 2026 George Chidera Akor, Love Allen Chijioke Ahakonye, Jae Min Lee, Dong-Seong Kim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
