"""Corroboration probes for survivors (NOT pins)."""
import sys, json
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from probe import load
wt = sys.argv[1]; h = load(wt)
def shep(sc):
    r = h.run_shepherd(h.CONTROL, h.default_scenario(**sc)); return h.dispatched_shas(r.calls)
H = h.HEAD_SHA
out = {
 "K6b build check-run (failure) only, no status -> expect []": shep({"check_runs_by_sha": {H: {"check_runs": [{"name": "build", "conclusion": "failure"}]}}}),
 "K6c only a non-build status (karen-qa) -> expect [HEAD]": shep({"combined_status_by_sha": {H: {"statuses": [{"context": "karen-qa", "state": "success"}]}}}),
 "K6d only a non-build check run (CodeQL) -> expect [HEAD]": shep({"check_runs_by_sha": {H: {"check_runs": [{"name": "CodeQL", "conclusion": "success"}]}}}),
}
r = h.run_publish(h.CONTROL)
out["B1-c/e publish GET pulls path -> expect repos/.../pulls/480"] = [p for c in r.calls for p in c.get("positionals", []) if "/pulls/" in p]
for k, v in out.items(): print(f"{k}\t{json.dumps(v).replace(H, 'HEAD')}")
