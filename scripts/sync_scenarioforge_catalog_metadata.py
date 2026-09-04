#!/usr/bin/env python3
"""Regenerate portable ScenarioForge notes from the resolved research dataset."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT.parent / "scenarioforge-dataset"
MANIFEST_FIELD = re.compile(r"^(id|kind):\s*(.+?)\s*$")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _git_revision(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short=7", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _manifest_identity(path: Path) -> tuple[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = MANIFEST_FIELD.match(line)
        if not match:
            continue
        fields[match.group(1)] = match.group(2).strip().strip("'\"")
    generator_id = fields.get("id", "")
    kind = fields.get("kind", "")
    if not generator_id or kind not in {"flag-generator", "flag-node-generator"}:
        raise ValueError(f"Could not read stable id/kind from {path}")
    return kind, generator_id


def _evidence(dataset_revision: str) -> dict[str, Any]:
    return {
        "dataset": f"scenarioforge-dataset@{dataset_revision}",
        "paper": "IEEE TPS ScenarioForge evaluation",
        "resolved_scenarios": 226,
        "successful_scenarios": 226,
        "validated_vulhub_recipes": 294,
        "validated_flag_node_generators": 85,
    }


def _sync_generator_notes(selections: dict[str, Any], evidence: dict[str, Any]) -> int:
    pack_path = ROOT / "pack.json"
    pack = _read_json(pack_path)
    existing_notes = {
        (str(item.get("kind") or ""), str(item.get("generator_id") or "")): item
        for item in pack.get("catalog_notes", [])
        if isinstance(item, dict)
    }
    disabled_items = {
        (str(item.get("kind") or ""), str(item.get("generator_id") or ""))
        for item in pack.get("catalog_items", [])
        if isinstance(item, dict) and item.get("disabled") is True
    }
    coverage = {
        str(generator_id): int(count)
        for generator_id, count in (selections.get("flag_node_generators") or {}).items()
    }
    manifests = sorted((ROOT / "flag_generators").rglob("manifest.y*ml"))
    manifests += sorted((ROOT / "flag_node_generators").rglob("manifest.y*ml"))
    identities = [_manifest_identity(path) for path in manifests]
    identity_set = set(identities)
    if len(identities) != 148 or len(identity_set) != 148:
        raise ValueError(
            f"Expected 148 unique generator identities, found {len(identity_set)}"
        )

    notes: list[dict[str, str]] = []
    for kind, generator_id in sorted(identity_set):
        existing = existing_notes.get((kind, generator_id))
        if (kind, generator_id) in disabled_items:
            if not existing or str(existing.get("note_color") or "") not in {
                "red",
                "yellow",
            }:
                raise ValueError(
                    f"Disabled generator {generator_id!r} needs a red/yellow explanation"
                )
            note = str(existing.get("note") or "").strip()
            color = str(existing.get("note_color") or "").strip()
        elif kind == "flag-node-generator":
            count = coverage.get(generator_id)
            if count is None:
                raise ValueError(
                    f"Enabled flag-node generator {generator_id!r} has no dataset coverage"
                )
            suffix = "scenario" if count == 1 else "scenarios"
            note = (
                "Validated successfully with live artifact checks and exercised in "
                f"{count} resolved IEEE TPS dataset {suffix}; enabled for Flow selection."
            )
            color = "green"
        else:
            note = (
                "Passed ScenarioForge catalog testing; enabled as a reusable artifact "
                "generator. The IEEE TPS execution dataset validates the downstream "
                "sequencing, deployment, and live-check pipeline."
            )
            color = "green"
        notes.append(
            {
                "kind": kind,
                "generator_id": generator_id,
                "note": note,
                "note_color": color,
            }
        )

    covered_node_ids = {
        generator_id
        for kind, generator_id in identity_set
        if kind == "flag-node-generator" and generator_id in coverage
    }
    if covered_node_ids != set(coverage):
        missing = sorted(set(coverage) - covered_node_ids)
        raise ValueError(f"Dataset references unknown flag-node generators: {missing}")
    if sum(item["note_color"] == "green" for item in notes) != 144:
        raise ValueError("Expected 144 enabled/green generator notes")

    pack["metadata_evidence"] = evidence
    pack["catalog_notes"] = notes
    _write_json(pack_path, pack)
    return len(notes)


def _sync_vulhub_notes(selections: dict[str, Any], evidence: dict[str, Any]) -> int:
    notes_path = ROOT / "vulnhub" / ".scenarioforge" / "catalog_notes.json"
    notes_doc = _read_json(notes_path)
    existing_notes = {
        str(item.get("compose_rel") or ""): item
        for item in notes_doc.get("notes", [])
        if isinstance(item, dict)
    }
    eligible = {
        str(key).split("|", 1)[0]
        for key in (selections.get("vulnerabilities") or {})
    }
    use_counts = Counter(
        str(vulnerability)
        for run in selections.get("selections", [])
        if isinstance(run, dict)
        for vulnerability in run.get("vulnerabilities", [])
    )
    compose_paths = sorted(
        path.relative_to(ROOT / "vulnhub").as_posix()
        for path in (ROOT / "vulnhub" / "content").rglob("docker-compose.yml")
    )
    if len(compose_paths) != 306:
        raise ValueError(f"Expected 306 Vulhub recipes, found {len(compose_paths)}")

    notes: list[dict[str, str]] = []
    seen_eligible: set[str] = set()
    for compose_rel in compose_paths:
        catalog_id = compose_rel.removeprefix("content/").removesuffix(
            "/docker-compose.yml"
        )
        existing = existing_notes.get(compose_rel)
        if catalog_id in eligible:
            seen_eligible.add(catalog_id)
            count = int(use_counts.get(catalog_id, 0))
            if count:
                suffix = "scenario" if count == 1 else "scenarios"
                note = (
                    "Included in the validated 294-recipe IEEE TPS catalog and exercised "
                    f"in {count} resolved execution-dataset {suffix}; enabled for isolated-lab selection."
                )
            else:
                note = (
                    "Included in the validated 294-recipe IEEE TPS catalog and its complete "
                    "coverage evidence; enabled for isolated-lab selection."
                )
            color = "green"
        elif existing and str(existing.get("note_color") or "") == "red":
            note = str(existing.get("note") or "").strip()
            color = "red"
        else:
            raise ValueError(f"Vulhub recipe lacks eligibility or exclusion evidence: {catalog_id}")
        notes.append(
            {
                "compose_rel": compose_rel,
                "note": note,
                "note_color": color,
            }
        )

    if seen_eligible != eligible:
        missing = sorted(eligible - seen_eligible)
        raise ValueError(f"Dataset references unknown Vulhub recipes: {missing}")
    if sum(item["note_color"] == "green" for item in notes) != 294:
        raise ValueError("Expected 294 enabled/green Vulhub notes")
    if sum(item["note_color"] == "red" for item in notes) != 12:
        raise ValueError("Expected 12 excluded/red Vulhub notes")

    notes_doc["evidence"] = evidence
    notes_doc["notes"] = notes
    _write_json(notes_path, notes_doc)

    items_path = ROOT / "vulnhub" / ".scenarioforge" / "catalog_items.json"
    items_doc = _read_json(items_path)
    items_doc["evidence"] = evidence
    _write_json(items_path, items_doc)
    return len(notes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="scenarioforge-dataset checkout (default: sibling repository)",
    )
    args = parser.parse_args()
    dataset = args.dataset.resolve()
    selections = _read_json(
        dataset / "dataset-resolved" / "catalog-selections.json"
    )
    if int(selections.get("resolved_spec_count") or 0) != 226:
        raise ValueError("Expected the 226-scenario resolved dataset")
    if int(selections.get("eligible_generator_count") or 0) != 85:
        raise ValueError("Expected 85 eligible flag-node generators")
    if int(selections.get("eligible_vulnerability_count") or 0) != 294:
        raise ValueError("Expected 294 eligible Vulhub recipes")

    evidence = _evidence(_git_revision(dataset))
    generator_count = _sync_generator_notes(selections, evidence)
    vulnerability_count = _sync_vulhub_notes(selections, evidence)
    print(
        f"Wrote {generator_count} generator notes and "
        f"{vulnerability_count} Vulhub notes from {evidence['dataset']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
