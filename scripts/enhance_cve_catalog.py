#!/usr/bin/env python3
"""Enhance a verified catalog snapshot without requesting NVD or CISA data."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import sync_cve_catalog as catalog  # noqa: E402
from scripts import validate_cve_catalog as validator  # noqa: E402


def verified_records(root: Path, manifest: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Replay manifest-pinned facts; an incomplete or changed shard fails closed."""
    for entry in manifest["shard_manifest"]:
        path = catalog._existing_catalog_file(root, entry["path"])
        compressed = path.read_bytes()
        if len(compressed) != entry["bytes"] or catalog.hash_bytes(compressed) != entry["sha256"]:
            raise ValueError("catalog changed during AI queue read")
        payload = gzip.decompress(compressed)
        if len(payload) != entry["uncompressed_bytes"]:
            raise ValueError("invalid uncompressed shard size")
        lines = payload.splitlines()
        if len(lines) != entry["records"]:
            raise ValueError("invalid shard record count")
        for line in lines:
            record = json.loads(line)
            # Only the source-fingerprint-validated cache may reattach an AI
            # result. An embedded result from an older snapshot is not proof.
            record.pop("ai_enrichment", None)
            yield record


def enhance_snapshot(
    root: Path, content: Path, cache_path: Path, recipe_manifest: Path,
    *, limit: int, client: Any, dry_run: bool = False, priority_cve_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    manifest_path = root / "manifest.json"
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    validation = validator.validate(root, content)
    if not validation["ok"]:
        raise ValueError("AI input catalog failed validation: " + "; ".join(validation["failures"]))
    cache = catalog.EnrichmentCache.load(cache_path)
    # The queue is derived from source fingerprints. Valid cached records are
    # retained, not charged again merely because time elapsed or AI ran before.
    cache.select_candidates(verified_records(root, manifest), limit=limit,
                            refresh_existing=False, priority_cve_ids=priority_cve_ids)
    if cache.stats["selected"] == 0 or client is None:
        return {"stage": "enhancement", "source_manifest_sha256": hashlib.sha256(original).hexdigest(),
                "source_updated_at": manifest["catalog_updated_at"], "scope": manifest["scope"],
                "totals": manifest["totals"], "ai_enrichment": {**cache.stats, "api_enabled": client is not None},
                "generated_recipes": {"deleted": 0}, "dry_run": dry_run}
    manager = catalog.GeneratedRecipeManager(content, recipe_manifest, dry_run=dry_run, partial=True)
    archetypes = json.loads((root / "archetypes.json").read_bytes())
    for record in cache.apply(verified_records(root, manifest), client=client):
        manager.consider(catalog.normalize_catalog_output_record(record), archetypes=archetypes)
    if manifest_path.read_bytes() != original:
        raise ValueError("source snapshot changed during AI enhancement")
    if cache.stats["generated"] == 0:
        return {"stage": "enhancement", "source_manifest_sha256": hashlib.sha256(original).hexdigest(),
                "source_updated_at": manifest["catalog_updated_at"], "scope": manifest["scope"],
                "totals": manifest["totals"], "ai_enrichment": {**cache.stats, "api_enabled": client is not None,
                "provider_error": cache.provider_error}, "generated_recipes": {"deleted": 0}, "dry_run": dry_run}
    cache.write(dry_run=dry_run)
    generated = manager.reconcile()
    if not dry_run:
        # This existing path reattaches only source-matching enhancements and
        # explicitly preserves source timestamps, sources, scope, and CVE count.
        catalog.rebuild_markdown_inventory(root, content, enrichment_cache_path=cache_path)
    final_manifest = json.loads(manifest_path.read_bytes())
    if final_manifest["catalog_updated_at"] != manifest["catalog_updated_at"] or final_manifest["sources"] != manifest["sources"]:
        raise ValueError("AI stage changed factual source provenance")
    if not dry_run:
        final_manifest.setdefault("pipeline", {})["schema_version"] = 1
        final_manifest.setdefault("pipeline", {})["enhancement"] = {
            "generation_completed_at": catalog.utc_now().isoformat(),
            "source_manifest_sha256": hashlib.sha256(original).hexdigest(),
            "source_updated_at": manifest["catalog_updated_at"],
            "revision": final_manifest["shard_set_sha256"],
        }
        temporary = manifest_path.with_suffix(".json.tmp")
        temporary.write_bytes(catalog.json_bytes(final_manifest, pretty=True))
        os.replace(temporary, manifest_path)
    return {
        "stage": "enhancement", "source_manifest_sha256": hashlib.sha256(original).hexdigest(),
        "source_updated_at": manifest["catalog_updated_at"],
        "scope": final_manifest["scope"], "totals": final_manifest["totals"],
        "ai_enrichment": {**cache.stats, "api_enabled": client is not None,
                          "provider_error": cache.provider_error},
        "generated_recipes": generated, "dry_run": dry_run,
    }


def _main() -> int:
    args = catalog.parse_args()
    # Reuse the already configured provider, model, key, request cap, retry
    # backoff and circuit breaker. No source API or alternate provider is used.
    key = os.environ.get("XAI_API_KEY", "").strip()
    client = (
        catalog.XAIEnricher(key, model=args.xai_model)
        if key and not (args.dry_run or args.offline or args.disable_ai_enrichment)
        else None
    )
    report = enhance_snapshot(
        catalog.resolve_path(args.output_dir), catalog.resolve_path(args.content_dir),
        catalog.resolve_path(args.enrichment_cache), catalog.resolve_path(args.generated_recipe_manifest),
        limit=args.ai_enrichment_limit, client=client, dry_run=args.dry_run,
        priority_cve_ids=args.priority_cve_ids,
    )
    if args.run_report:
        target = catalog.resolve_path(args.run_report)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, target)
    print(json.dumps(report, indent=2))
    metrics = report["ai_enrichment"]
    return int(metrics["selected"] > 0 and metrics["generated"] == 0)


def main() -> int:
    from scripts.cve_catalog_release import _target_lock
    output = catalog.resolve_path(catalog.parse_args().output_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    with _target_lock(output):
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
