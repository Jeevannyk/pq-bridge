"""Export the project's main JSON evidence to readable CSV files (open in Excel): python data/export_csv.py -> data/exports/"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "exports"
OUT.mkdir(exist_ok=True)


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(name, header, rows):
    rows = list(rows)
    with open(OUT / name, "w", newline="", encoding="utf-8-sig") as f:   # BOM so Excel reads UTF-8
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"{name:32s} {len(rows):5d} rows")


# ML training data: the labelled lines and where they came from
labels = [json.loads(l) for l in (ROOT / "data/labels/lines.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
write("ml_training_dataset.csv", ["repo", "file", "line", "code", "label", "is_test", "is_config"],
      [(r["repo"], r["file"], r["line"], r["text"], "outdated" if r["label"] else "safe", r["is_test"], r["is_config"]) for r in labels])
write("ml_training_repos.csv", ["repo", "url", "commit"], [(r["name"], r["url"], r["commit"]) for r in load("data/repos.json")])

# ML evaluation (leave-one-repo-out)
ev = load("evidence/ml_eval.json")
write("ml_eval_methods.csv", ["method", "precision", "recall", "f1", "tp", "fp", "fn"],
      [(k, v["precision"], v["recall"], v["f1"], v["tp"], v["fp"], v["fn"]) for k, v in ev["methods"].items()])
write("ml_eval_per_repo.csv", ["repo", "labelled_lines", "tp", "fp", "fn"],
      [(k, v["n"], v["tp"], v["fp"], v["fn"]) for k, v in ev["per_repo_hybrid"].items()])
write("ml_eval_errors.csv", ["repo", "file", "line", "code", "true_label", "ml_probability", "rule_fired"],
      [(e["repo"], e["file"], e["line"], e["text"], "outdated" if e["label"] else "safe", e["p"], e["rule"]) for e in ev["errors"]])

# Findings on the 11 real repos
rf = load("evidence/repo_findings.json")["findings"]
write("real_repo_findings.csv", ["repo", "file", "line", "code", "primitive", "ml_p", "status", "severity", "banking_context", "detected_by", "is_test"],
      [(f["repo"], f["file"], f["line"], f["snippet"], f["primitive"], f["ml_p"], f["status"], f["severity"], f["banking_context"], f["detected_by"], f["is_test"]) for f in rf])

# PQBank scan, risk, plan
write("pqbank_findings.csv", ["service", "file", "line", "category", "algorithm", "status", "severity", "detected_by", "ml_p", "evidence"],
      [(f.get("service"), f["file"], f["line"], f["category"], f["algorithm"], f["status"], f.get("severity"), f.get("detected_by", "exact parser"),
        f.get("ml_p"), f["snippet"]) for f in load("evidence/inventory.json")])
risk = load("evidence/risk.json")
write("pqbank_risk_services.csv", ["service", "risk_score", "findings", "shelf_life_years_X", "migration_years_Y", "crqc_years_Z", "at_risk", "exposure", "criticality"],
      [(s, v["score"], v["findings"], v["mosca"]["X"], v["mosca"]["Y"], v["mosca"]["Z"], v["mosca"]["at_risk"], v["exposure"], v["criticality"]) for s, v in risk["services"].items()])
plan = load("evidence/plan.json")
write("pqbank_migration_plan.csv", ["task", "window", "risk"],
      sorted(((t, w, plan["risks"].get(t)) for t, w in plan["plan"].items()), key=lambda r: (r[1], r[0])))
pr = plan["primary"]
write("pqbank_plan_solvers.csv", ["solver", "objective", "violations", "optimality_gap_pct"],
      [(pr["solver"], pr["objective"], len(pr["violations"]), pr["optimality_gap_pct"])]
      + [(k, v["objective"], len(v["violations"]), "") for k, v in plan["baselines"].items()])

# Live crypto state of the bank
state = load("testbed/runtime/state/services.json")
write("pqbank_crypto_state.csv", ["service", "setting", "value"],
      [(s, k, json.dumps(v) if isinstance(v, (list, dict)) else v) for s, cfg in state.items() for k, v in cfg.items()])
hist = ROOT / "testbed/runtime/state/history.json"
if hist.exists():
    h = json.loads(hist.read_text(encoding="utf-8"))
    write("pqbank_migration_history.csv", ["label", "tasks", "time"], [(e.get("label"), ", ".join(e.get("tasks", [])), e.get("ts") or e.get("time")) for e in h])

# Real-world TLS survey and benchmarks
write("tls_survey_real_banks.csv", ["host", "protocol", "key_exchange", "pq_key_exchange", "certificate_signature", "leaf_key_bits", "issuer"],
      [(r["host"], r.get("protocol"), r.get("group"), r.get("pq_kex"), r.get("peer_sig"), r.get("leaf_key_bits"), r.get("issuer")) for r in load("evidence/tls_survey.json")["rows"] if r.get("ok")])
bm = load("evidence/benchmarks.json")
write("bench_tls.csv", ["mode", "key_exchange", "certificate_signature", "server_to_client_B", "client_to_server_B", "total_B", "median_ms", "p95_ms", "handshakes_per_s"],
      [(b["mode"], b["group"], b["peer_sig"], b["bytes_server_to_client"], b["bytes_client_to_server"], b["bytes_total"], b["median_ms"], b["p95_ms"], b["handshakes_per_s"]) for b in bm["tls"]])
write("bench_signed.csv", ["item", "algorithm", "signature_B", "payload_B", "sign_ms", "verify_ms"],
      [(b["item"], b["algorithm"], b["signature_bytes"], b["payload_bytes"], b["sign_ms"], b["verify_ms"]) for b in bm["signed"]])
