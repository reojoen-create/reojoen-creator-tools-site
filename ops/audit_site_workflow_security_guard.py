#!/usr/bin/env python3
"""Fail-closed security guard for the public YouTube API audit/compliance site workflows."""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)

EXPECTED_PINS = {
    ".github/workflows/pages.yml": {
        "actions/checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",
        "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
        "actions/upload-pages-artifact": "7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
        "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
    },
    ".github/workflows/site-health.yml": {
        "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    },
}

EXPECTED_PERMISSIONS = {
    ".github/workflows/pages.yml": {
        "contents": "read",
        "pages": "write",
        "id-token": "write",
    },
    ".github/workflows/site-health.yml": {
        "contents": "read",
    },
}


def _top_level_mapping(text: str, key: str) -> Dict[str, str]:
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == f"{key}:":
            start = i + 1
            break
    if start is None:
        raise AssertionError(f"MISSING_TOP_LEVEL_{key.upper()}")
    out: Dict[str, str] = {}
    for line in lines[start:]:
        if line and not line.startswith((" ", "\t")):
            break
        m = re.match(r"^\s{2}([A-Za-z0-9_-]+):\s*([^#\s]+)\s*(?:#.*)?$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _extract_uses(text: str) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for raw in USES_RE.findall(text):
        if raw.startswith("./"):
            continue
        if "@" not in raw:
            raise AssertionError(f"ACTION_REF_MISSING_AT:{raw}")
        action, ref = raw.rsplit("@", 1)
        if not SHA40.fullmatch(ref):
            raise AssertionError(f"ACTION_REF_NOT_IMMUTABLE_SHA:{raw}")
        found.append((action, ref))
    return found


def validate_workflow(path: str, text: str) -> None:
    expected_pins = EXPECTED_PINS[path]
    actual_uses = _extract_uses(text)
    if dict(actual_uses) != expected_pins or len(actual_uses) != len(expected_pins):
        raise AssertionError(
            f"ACTION_PIN_SET_MISMATCH:{path}:expected={expected_pins}:actual={actual_uses}"
        )

    actual_permissions = _top_level_mapping(text, "permissions")
    if actual_permissions != EXPECTED_PERMISSIONS[path]:
        raise AssertionError(
            f"PERMISSIONS_MISMATCH:{path}:expected={EXPECTED_PERMISSIONS[path]}:actual={actual_permissions}"
        )

    if "timeout-minutes:" not in text:
        raise AssertionError(f"TIMEOUT_MISSING:{path}")

    if path.endswith("pages.yml"):
        required = [
            "branches: [main]",
            "environment:",
            "name: github-pages",
            "cancel-in-progress: false",
        ]
        forbidden = ["pull_request:", "pull_request_target:"]
    else:
        required = [
            'cron: "17 */6 * * *"',
            "BASE_URL: https://reojoen-create.github.io/reojoen-creator-tools-site",
            "cancel-in-progress: true",
            "Verify three public HTTPS audit URLs",
            "secret_values_exposed':False",
        ]
        forbidden = ["pull_request_target:"]

    for marker in required:
        if marker not in text:
            raise AssertionError(f"REQUIRED_MARKER_MISSING:{path}:{marker}")
    for marker in forbidden:
        if marker in text:
            raise AssertionError(f"FORBIDDEN_TRIGGER_PRESENT:{path}:{marker}")


def validate_repo(root: Path) -> dict:
    checked = []
    for rel in EXPECTED_PINS:
        path = root / rel
        if not path.is_file():
            raise AssertionError(f"WORKFLOW_MISSING:{rel}")
        text = path.read_text(encoding="utf-8")
        validate_workflow(rel, text)
        checked.append(rel)
    return {
        "schema": "reojoen_audit_site_workflow_security/v1",
        "status": "PASS",
        "checked_workflows": checked,
        "immutable_action_count": sum(len(v) for v in EXPECTED_PINS.values()),
        "secret_values_exposed": False,
    }


def self_test(root: Path) -> dict:
    originals = {
        rel: (root / rel).read_text(encoding="utf-8") for rel in EXPECTED_PINS
    }
    cases = []

    def must_fail(name: str, rel: str, mutated: str, expected_fragment: str) -> None:
        try:
            validate_workflow(rel, mutated)
        except AssertionError as exc:
            if expected_fragment not in str(exc):
                raise AssertionError(f"SELF_TEST_WRONG_FAILURE:{name}:{exc}") from exc
            cases.append({"case": name, "status": "PASS"})
            return
        raise AssertionError(f"SELF_TEST_DID_NOT_FAIL:{name}")

    pages = originals[".github/workflows/pages.yml"]
    health = originals[".github/workflows/site-health.yml"]

    must_fail(
        "floating_action_tag",
        ".github/workflows/pages.yml",
        pages.replace(
            "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
            "actions/checkout@v6",
            1,
        ),
        "ACTION_REF_NOT_IMMUTABLE_SHA",
    )
    must_fail(
        "pages_permission_drift",
        ".github/workflows/pages.yml",
        pages.replace("  pages: write", "  pages: read", 1),
        "PERMISSIONS_MISMATCH",
    )
    must_fail(
        "health_permission_escalation",
        ".github/workflows/site-health.yml",
        health.replace("  contents: read", "  contents: write", 1),
        "PERMISSIONS_MISMATCH",
    )
    must_fail(
        "health_schedule_drift",
        ".github/workflows/site-health.yml",
        health.replace('cron: "17 */6 * * *"', 'cron: "0 0 * * *"', 1),
        "REQUIRED_MARKER_MISSING",
    )

    return {
        "schema": "reojoen_audit_site_workflow_security_selftest/v1",
        "status": "PASS",
        "cases": cases,
        "secret_values_exposed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", default="audit-site-workflow-security.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    payload = self_test(root) if args.self_test else validate_repo(root)
    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
