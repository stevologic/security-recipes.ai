#!/usr/bin/env python3
"""Validate marketplace registries and the public schema dependency graph."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_DIR = Path("data/marketplace")
SCHEMA_DIR = Path("static/marketplace-schemas")
SCHEMA_URL_PREFIX = "/marketplace-schemas/"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_INDEX_VERSION = "securityrecipes.marketplace.schemas.v1"


class ValidationError(ValueError):
    """Raised when marketplace data contains broken identity or reference links."""


@dataclass(frozen=True)
class ValidationSummary:
    input_channels: int
    output_channels: int
    report_profiles: int
    workflow_templates: int
    strategic_tracks: int
    schemas: int
    local_schema_references: int


def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise ValidationError(f"required JSON file is missing: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"could not parse {path}: {exc}") from exc


def _mapping(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{label} must be an object")
    return {}


def _list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if isinstance(value, list):
        return value
    errors.append(f"{label} must be an array")
    return []


def _registry(
    document: dict[str, Any],
    collection_key: str,
    label: str,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    entries = _list(document.get(collection_key), f"{label}.{collection_key}", errors)
    result: dict[str, dict[str, Any]] = {}
    for index, raw_entry in enumerate(entries):
        entry = _mapping(raw_entry, f"{label}.{collection_key}[{index}]", errors)
        entity_id = entry.get("id")
        if not isinstance(entity_id, str) or not entity_id.strip():
            errors.append(f"{label}.{collection_key}[{index}].id must be a non-empty string")
            continue
        if entity_id in result:
            errors.append(f"duplicate {label} ID: {entity_id}")
            continue
        result[entity_id] = entry
    return result


def _check_unique_values(values: Any, label: str, errors: list[str]) -> list[str]:
    items = _list(values, label, errors)
    result: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(items):
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label}[{index}] must be a non-empty string")
            continue
        if value in seen:
            errors.append(f"{label} contains duplicate reference: {value}")
            continue
        seen.add(value)
        result.append(value)
    return result


def _check_reference(value: Any, allowed: set[str], label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} must be a non-empty string reference")
    elif value not in allowed:
        errors.append(f"{label} references unknown ID {value!r}")


def _check_reference_list(values: Any, allowed: set[str], label: str, errors: list[str]) -> None:
    for index, value in enumerate(_check_unique_values(values, label, errors)):
        _check_reference(value, allowed, f"{label}[{index}]", errors)


def _check_exact_keys(
    actual: set[str],
    expected: set[str],
    label: str,
    expected_label: str,
    errors: list[str],
) -> None:
    missing = sorted(expected - actual)
    stale = sorted(actual - expected)
    if missing:
        errors.append(f"{label} is missing {expected_label}: {', '.join(missing)}")
    if stale:
        errors.append(f"{label} contains unreferenced keys: {', '.join(stale)}")


def _validate_marketplace_data(repo_root: Path, errors: list[str]) -> tuple[dict[str, int], int]:
    data_dir = repo_root / MARKETPLACE_DIR
    inputs_doc = _mapping(_load_json(data_dir / "input_channels.json"), "input_channels.json", errors)
    outputs_doc = _mapping(_load_json(data_dir / "output_channels.json"), "output_channels.json", errors)
    reports_doc = _mapping(_load_json(data_dir / "report_profiles.json"), "report_profiles.json", errors)
    workflows_doc = _mapping(_load_json(data_dir / "workflow_templates.json"), "workflow_templates.json", errors)
    readiness = _mapping(_load_json(data_dir / "readiness_profiles.json"), "readiness_profiles.json", errors)
    catalog = _mapping(_load_json(data_dir / "catalog.json"), "catalog.json", errors)

    inputs = _registry(inputs_doc, "channels", "input channels", errors)
    outputs = _registry(outputs_doc, "channels", "output channels", errors)
    reports = _registry(reports_doc, "profiles", "report profiles", errors)
    workflows = _registry(workflows_doc, "templates", "workflow templates", errors)
    tracks = _registry(catalog, "strategic_tracks", "catalog", errors)

    namespaces = {
        "input channel": inputs,
        "output channel": outputs,
        "report profile": reports,
        "workflow template": workflows,
        "strategic track": tracks,
    }
    global_ids: dict[str, str] = {}
    for namespace, registry in namespaces.items():
        for entity_id in registry:
            previous = global_ids.setdefault(entity_id, namespace)
            if previous != namespace:
                errors.append(f"marketplace ID {entity_id!r} is ambiguous across {previous} and {namespace}")

    input_ids = set(inputs)
    output_ids = set(outputs)
    report_ids = set(reports)
    pack_ids = input_ids | output_ids

    for template_id, template in workflows.items():
        prefix = f"workflow template {template_id}"
        _check_reference(template.get("default_report_profile_id"), report_ids, f"{prefix}.default_report_profile_id", errors)
        _check_reference(template.get("default_output_channel_id"), output_ids, f"{prefix}.default_output_channel_id", errors)
        _check_reference_list(template.get("default_input_channel_ids"), input_ids, f"{prefix}.default_input_channel_ids", errors)

    signals = _list(catalog.get("market_signals"), "catalog.market_signals", errors)
    signal_sources: set[str] = set()
    for index, raw_signal in enumerate(signals):
        signal = _mapping(raw_signal, f"catalog.market_signals[{index}]", errors)
        source = signal.get("source")
        if not isinstance(source, str) or not source.strip():
            errors.append(f"catalog.market_signals[{index}].source must be a non-empty string")
        elif source in signal_sources:
            errors.append(f"duplicate catalog market signal source: {source}")
        else:
            signal_sources.add(source)

    for track_id, track in tracks.items():
        prefix = f"catalog strategic track {track_id}"
        _check_reference_list(track.get("pack_ids"), pack_ids, f"{prefix}.pack_ids", errors)
        _check_reference_list(
            track.get("market_signal_sources"),
            signal_sources,
            f"{prefix}.market_signal_sources",
            errors,
        )

    runtime_labels = _mapping(readiness.get("runtime_labels"), "readiness.runtime_labels", errors)
    runtime_requirements = _mapping(readiness.get("runtime_requirements"), "readiness.runtime_requirements", errors)
    runtime_blockers = _mapping(readiness.get("runtime_blockers"), "readiness.runtime_blockers", errors)
    runtime_keys = set(runtime_labels)
    _check_exact_keys(
        set(runtime_requirements), runtime_keys, "readiness.runtime_requirements", "runtime definitions", errors
    )
    _check_exact_keys(set(runtime_blockers), runtime_keys, "readiness.runtime_blockers", "runtime definitions", errors)

    auth_labels = _mapping(readiness.get("auth_mode_labels"), "readiness.auth_mode_labels", errors)
    auth_details = _mapping(readiness.get("auth_mode_details"), "readiness.auth_mode_details", errors)
    auth_keys = set(auth_labels)
    _check_exact_keys(set(auth_details), auth_keys, "readiness.auth_mode_details", "auth-mode definitions", errors)

    output_auth = _mapping(
        readiness.get("output_driver_auth_modes"),
        "readiness.output_driver_auth_modes",
        errors,
    )
    output_drivers: set[str] = set()
    for channel_id, channel in inputs.items():
        prefix = f"input channel {channel_id}"
        _check_reference(channel.get("runtime_support"), runtime_keys, f"{prefix}.runtime_support", errors)
        _check_reference_list(channel.get("auth_modes"), auth_keys, f"{prefix}.auth_modes", errors)

    for channel_id, channel in outputs.items():
        prefix = f"output channel {channel_id}"
        _check_reference(channel.get("runtime_support"), runtime_keys, f"{prefix}.runtime_support", errors)
        driver = channel.get("driver")
        if not isinstance(driver, str) or not driver.strip():
            errors.append(f"{prefix}.driver must be a non-empty string")
            continue
        output_drivers.add(driver)

    _check_exact_keys(
        set(output_auth), output_drivers, "readiness.output_driver_auth_modes", "output drivers", errors
    )
    for driver, modes in output_auth.items():
        _check_reference_list(modes, auth_keys, f"readiness.output_driver_auth_modes.{driver}", errors)

    counts = {
        "input_channels": len(inputs),
        "output_channels": len(outputs),
        "report_profiles": len(reports),
        "workflow_templates": len(workflows),
        "strategic_tracks": len(tracks),
    }
    return counts, len(signals)


def _repo_relative_file(repo_root: Path, value: str, label: str, errors: list[str]) -> Path | None:
    posix_path = PurePosixPath(value)
    if posix_path.is_absolute() or not posix_path.parts or any(part in {"", ".", ".."} for part in posix_path.parts):
        errors.append(f"{label} is not a safe repository-relative path: {value!r}")
        return None
    target = repo_root.joinpath(*posix_path.parts)
    if not target.is_file():
        errors.append(f"{label} does not resolve to a file: {value}")
        return None
    try:
        target.resolve().relative_to(repo_root.resolve())
    except ValueError:
        errors.append(f"{label} resolves outside the repository: {value}")
        return None
    return target


def _snake_case(value: str) -> str:
    result: list[str] = []
    for index, character in enumerate(value):
        if character.isupper() and index and (value[index - 1].islower() or value[index - 1].isdigit()):
            result.append("_")
        result.append(character.lower() if character.isalnum() else "_")
    return "_".join(part for part in "".join(result).split("_") if part)


def _iter_schema_refs(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "$ref":
                yield child_path, child
            yield from _iter_schema_refs(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_schema_refs(child, f"{path}[{index}]")


def _decode_pointer_token(token: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(token):
        if token[index] != "~":
            result.append(token[index])
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise KeyError(f"invalid JSON Pointer escape in {token!r}")
        result.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(result)


def _resolve_json_pointer(document: Any, fragment: str) -> Any:
    pointer = unquote(fragment)
    if not pointer:
        return document
    if not pointer.startswith("/"):
        raise KeyError(f"fragment is not a JSON Pointer: #{fragment}")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = _decode_pointer_token(raw_token)
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise KeyError(f"JSON Pointer segment {token!r} does not exist")
    return current


def _validate_schema_index(repo_root: Path, errors: list[str]) -> tuple[int, int]:
    schema_dir = repo_root / SCHEMA_DIR
    index_path = schema_dir / "index.json"
    index = _mapping(_load_json(index_path), "marketplace schema index", errors)
    entries = _list(index.get("schemas"), "marketplace schema index.schemas", errors)
    if index.get("schema_version") != SCHEMA_INDEX_VERSION:
        errors.append(f"marketplace schema index.schema_version must be {SCHEMA_INDEX_VERSION!r}")

    href_to_schema: dict[str, dict[str, Any]] = {}
    href_to_filename: dict[str, str] = {}
    keys: set[str] = set()
    consumer_keys = {"index"}
    applies_to_count = 0
    for index_number, raw_entry in enumerate(entries):
        label = f"marketplace schema index.schemas[{index_number}]"
        entry = _mapping(raw_entry, label, errors)
        key = entry.get("key")
        if not isinstance(key, str) or not key.strip():
            errors.append(f"{label}.key must be a non-empty string")
        elif key in keys:
            errors.append(f"duplicate marketplace schema key: {key}")
        else:
            keys.add(key)
            consumer_key = _snake_case(key)
            if consumer_key in consumer_keys:
                errors.append(f"marketplace schema key {key!r} collides as consumer key {consumer_key!r}")
            consumer_keys.add(consumer_key)

        for metadata_field in ("label", "description"):
            metadata_value = entry.get(metadata_field)
            if not isinstance(metadata_value, str) or not metadata_value.strip():
                errors.append(f"{label}.{metadata_field} must be a non-empty string")

        href = entry.get("href")
        filename: str | None = None
        if not isinstance(href, str) or not href.startswith(SCHEMA_URL_PREFIX):
            errors.append(f"{label}.href must start with {SCHEMA_URL_PREFIX!r}")
        else:
            relative = href.removeprefix(SCHEMA_URL_PREFIX)
            candidate = PurePosixPath(relative)
            if (
                not relative.endswith(".schema.json")
                or candidate.is_absolute()
                or len(candidate.parts) != 1
                or candidate.name != relative
            ):
                errors.append(f"{label}.href is not a direct marketplace schema URL: {href}")
            else:
                filename = relative
                if href in href_to_filename:
                    errors.append(f"duplicate marketplace schema href: {href}")
                else:
                    href_to_filename[href] = filename

        applies_to = entry.get("applies_to")
        if not isinstance(applies_to, str) or not applies_to.strip():
            errors.append(f"{label}.applies_to must be a non-empty reference")
        elif applies_to.startswith("data/"):
            applies_to_count += 1
            _repo_relative_file(repo_root, applies_to, f"{label}.applies_to", errors)
        elif applies_to.startswith("browser local ") and len(applies_to) > len("browser local "):
            applies_to_count += 1
        else:
            errors.append(
                f"{label}.applies_to must resolve to an existing data/ file or a declared browser local target: {applies_to!r}"
            )

        if filename is not None:
            schema_path = schema_dir / filename
            if not schema_path.is_file():
                errors.append(f"{label}.href does not resolve to a schema file: {href}")
            else:
                schema = _mapping(_load_json(schema_path), filename, errors)
                href_to_schema[href] = schema
                if schema.get("$id") != href:
                    errors.append(f"{filename}.$id must exactly match its indexed href {href!r}")
                if schema.get("$schema") != JSON_SCHEMA_DIALECT:
                    errors.append(f"{filename}.$schema must be {JSON_SCHEMA_DIALECT!r}")

    actual_files = {
        path.relative_to(schema_dir).as_posix()
        for path in schema_dir.rglob("*.schema.json")
        if path.is_file()
    }
    owned_files = set(href_to_filename.values())
    unowned = sorted(actual_files - owned_files)
    missing = sorted(owned_files - actual_files)
    if unowned:
        errors.append(f"schema index does not own schema files: {', '.join(unowned)}")
    if missing:
        errors.append(f"schema index references missing schema files: {', '.join(missing)}")

    reference_count = 0
    for source_href, schema in href_to_schema.items():
        for ref_path, ref in _iter_schema_refs(schema):
            reference_count += 1
            if not isinstance(ref, str) or not ref:
                errors.append(f"{source_href} {ref_path} must be a non-empty string")
                continue
            if ref.startswith("#"):
                target_href = source_href
                fragment = ref[1:]
            elif ref.startswith(SCHEMA_URL_PREFIX):
                target_href, separator, fragment = ref.partition("#")
                if target_href not in href_to_schema:
                    errors.append(f"{source_href} {ref_path} references an unindexed schema: {target_href}")
                    continue
                if not separator:
                    fragment = ""
            else:
                errors.append(f"{source_href} {ref_path} uses an unsupported non-local $ref: {ref}")
                continue
            try:
                _resolve_json_pointer(href_to_schema[target_href], fragment)
            except KeyError as exc:
                errors.append(f"{source_href} {ref_path} does not resolve ({ref}): {exc}")

    if applies_to_count != len(entries):
        errors.append("not every indexed schema has a resolvable applies_to target")
    return len(href_to_schema), reference_count


def validate(repo_root: Path = REPO_ROOT) -> ValidationSummary:
    repo_root = repo_root.resolve()
    errors: list[str] = []
    counts, _signal_count = _validate_marketplace_data(repo_root, errors)
    schema_count, reference_count = _validate_schema_index(repo_root, errors)
    if errors:
        raise ValidationError("marketplace integrity validation failed:\n- " + "\n- ".join(errors))
    return ValidationSummary(
        **counts,
        schemas=schema_count,
        local_schema_references=reference_count,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="Repository root to validate.")
    args = parser.parse_args(argv)
    try:
        summary = validate(args.repo_root)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(
        "Marketplace integrity OK: "
        f"{summary.input_channels} inputs, {summary.output_channels} outputs, "
        f"{summary.report_profiles} reports, {summary.workflow_templates} workflows, "
        f"{summary.strategic_tracks} tracks, {summary.schemas} schemas, "
        f"{summary.local_schema_references} local schema references."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
