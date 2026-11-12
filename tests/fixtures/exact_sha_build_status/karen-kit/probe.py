"""External corroboration probes (NOT pins). Run against workflow files in a given worktree via its own harness."""
import importlib.util, sys, json
def load(wt):
    spec = importlib.util.spec_from_file_location("h", f"{wt}/tests/test_exact_sha_build_status_harness.py")
    m = importlib.util.module_from_spec(spec); sys.modules["h"] = m; spec.loader.exec_module(m); return m
def shepherd(h, branch, cross=False):
    pr = h.catalog_pr(branch=branch); pr["isCrossRepository"] = cross
    r = h.run_shepherd(h.CONTROL, h.default_scenario(pr_list=[pr]))
    return {"rc": r.completed.returncode, "dispatched": [c["fields"].get("expected_branch") for c in h.workflow_run_calls(r.calls)]}
def publish(h, pull=None, expected_branch=None, failures=0, result="success"):
    eb = expected_branch or h.SYNC_BRANCH
    sc = h.default_scenario(pull=pull or h.live_pull(branch=eb), status_post_failures=failures)
    r = h.run_publish(h.CONTROL, validate_result=result, expected_branch=eb, scenario=sc)
    posts = h.status_post_calls(r.calls)
    return {"rc": r.completed.returncode, "post_attempts": len(posts)}
def pull(h, **kw):
    p = h.live_pull()
    for k, v in kw.items():
        if k == "repo": p["head"]["repo"] = v
        elif k == "state": p["state"] = v
        elif k == "base": p["base"]["ref"] = v
        elif k == "ref": p["head"]["ref"] = v
    return p
BRANCHES = ["automation/cve-catalog-sync", "automation/cve-catalog-sync-2", "automation/cve-catalog-sync/x",
            "x/automation/cve-catalog-sync", "Automation/CVE-Catalog-Sync", "automation/cve-catalog-sync ",
            " automation/cve-catalog-sync", "automation/cve\u2010catalog\u2010sync", "automation/cve-catalog-sync\u200b",
            "refs/heads/automation/cve-catalog-sync", "automation/content-refresh-ir-si-monitor-isolation",
            "dependabot/npm_and_yarn/main/npm-minor-and-patch-3ce9b7b435", "fix/hold-cve-catalog-sync-notes", "automation/"]
if __name__ == "__main__":
    wt = sys.argv[1]; which = sys.argv[2:] or ["branches", "publish", "cap"]
    h = load(wt); out = {}
    if "branches" in which:
        for b in BRANCHES: out[f"shepherd {b!r}"] = shepherd(h, b)
        out["shepherd sync isCrossRepository=true"] = shepherd(h, h.SYNC_BRANCH, cross=True)
        for b in BRANCHES[1:]: out[f"publish expected_branch={b!r} live ref same"] = publish(h, pull=pull(h, ref=b), expected_branch=b)
    if "publish" in which:
        out["publish control (sync, open, same repo, base main)"] = publish(h)
        out["publish fork head repo evil/security-recipes.ai"] = publish(h, pull=pull(h, repo={"full_name": "evil/security-recipes.ai"}))
        out["publish head repo null (deleted fork)"] = publish(h, pull=pull(h, repo=None))
        out["publish PR closed"] = publish(h, pull=pull(h, state="closed"))
        out["publish base=release"] = publish(h, pull=pull(h, base="release"))
        out["publish live ref=content, expected=sync"] = publish(h, pull=pull(h, ref="automation/content-refresh-x"))
        out["publish live ref=sync, expected=content"] = publish(h, pull=pull(h), expected_branch="automation/content-refresh-x")
    if "cap" in which:
        for n in (0, 1, 3, 4, 5):
            out[f"cap: POST failures={n}"] = publish(h, failures=n)
    for k, v in out.items(): print(f"{k}\t{json.dumps(v)}")
