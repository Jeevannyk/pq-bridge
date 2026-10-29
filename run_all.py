"""Reproduce the full PQ-Bridge run from a clean, fully classical bank.

  python run_all.py            reset testbed, scan, real-repo ML analysis, TLS survey, plan, QCloud circuits,
                               every wave, fault drill, benchmarks, report
  python run_all.py --no-reset reuse the running testbed

All evidence lands in ./evidence (inventory, detection eval, risk, plan + QpiAI runs,
QAOA, QRNG health, wave gate results, before/after TLS traces, report).
"""
import json
import sys

from pqbridge import pipeline


def main():
    if "--no-reset" not in sys.argv:
        pipeline.reset()
    pipeline.scan()
    pipeline.repos()          # real bank / fintech repos -> hybrid ML detection engine
    pipeline.tls_survey()     # real public TLS posture
    pipeline.assess()
    plan = pipeline.plan()
    pipeline.circuits()       # QRNG / QAOA / Shor / Grover designs on QpiAI QCloud
    for i in range(len(plan["final_waves"])):
        rec = pipeline.run_wave(i)
        if not rec["passed"]:
            pipeline.log(f"wave {i} failed its gate and was rolled back; stopping here")
            break
    pipeline.drill()
    pipeline.benchmarks()     # classical vs hybrid vs PQ-only
    pipeline.scan()           # post-migration inventory
    rep = pipeline.report()
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
