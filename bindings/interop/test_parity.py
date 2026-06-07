"""Cross-binding parity guards: keep the Python and Node SDKs in sync.

These tests fail — locally via ``make interop`` and in CI — the moment the
two bindings drift apart:

* **API-surface parity** — the Python (``acdp-py``) binding, the Node
  (``acdp-node``) binding, and the shared manifest
  (``expected_surface.json``) MUST all expose the same classes and the
  same methods. Method names are normalized to snake_case so Node's
  camelCase compares equal. Adding a method to one binding without the
  other — or without updating the manifest — is a failure.

* **Version parity** — ``pyproject.toml``, both bindings' ``Cargo.toml``,
  and ``package.json`` MUST carry the same version.

The manifest is the single source of truth: when you intentionally change
the public API, update ``expected_surface.json`` in the same change and
both bindings to match.

Run from ``bindings/interop/`` (after building both bindings), or via
``make interop``.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

import acdp

from test_interop import NodeWorker  # reuse the JSON-RPC worker harness

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
MANIFEST = os.path.join(HERE, "expected_surface.json")


def _load_manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)["classes"]


def _python_surface(class_name: str) -> list[str]:
    """The public surface of a Python binding class, snake_case (already)."""
    cls = getattr(acdp, class_name)
    return sorted(n for n in dir(cls) if not n.startswith("_"))


# ── API-surface parity ───────────────────────────────────────────────────


@pytest.fixture(scope="module")
def node():
    if shutil.which("node") is None:
        pytest.skip("node executable not found on PATH")
    worker = NodeWorker()
    try:
        worker.call("ping")  # fail fast if the acdp-node binding is not built
        yield worker
    finally:
        worker.close()


def test_python_surface_matches_manifest():
    manifest = _load_manifest()
    for class_name, methods in manifest.items():
        assert _python_surface(class_name) == sorted(methods), (
            f"Python {class_name} surface drifted from expected_surface.json"
        )


def test_node_surface_matches_manifest(node):
    manifest = _load_manifest()
    described = node.call("describe")["classes"]
    for class_name, methods in manifest.items():
        assert class_name in described, f"Node binding missing class {class_name}"
        assert sorted(described[class_name]) == sorted(methods), (
            f"Node {class_name} surface drifted from expected_surface.json"
        )


def test_python_and_node_class_sets_match(node):
    described = node.call("describe")["classes"]
    manifest = _load_manifest()
    assert set(described) == set(manifest), "Node class set drifted from manifest"
    # And every manifest class is actually importable from the Python SDK.
    for class_name in manifest:
        assert hasattr(acdp, class_name), f"Python binding missing class {class_name}"


def test_python_and_node_method_sets_match_each_other(node):
    """The strongest sync assertion: per class, the two bindings expose an
    identical (snake_case-normalized) method set — independent of the
    manifest, so the bindings can never silently diverge from each other."""
    described = node.call("describe")["classes"]
    for class_name in _load_manifest():
        py = _python_surface(class_name)
        nd = sorted(described[class_name])
        assert py == nd, (
            f"{class_name} surface differs between bindings:\n"
            f"  python only: {sorted(set(py) - set(nd))}\n"
            f"  node only:   {sorted(set(nd) - set(py))}"
        )


# ── Version parity ───────────────────────────────────────────────────────


def _version_from_toml(path: str) -> str:
    """Read the package `version = "..."` from a TOML file without a TOML
    dependency (the line format is stable in these manifests)."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    raise AssertionError(f"no version found in {path}")


def _version_from_json(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["version"]


def test_binding_versions_are_in_sync():
    versions = {
        "acdp-py/pyproject.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-py", "pyproject.toml")
        ),
        "acdp-py/Cargo.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-py", "Cargo.toml")
        ),
        "acdp-node/Cargo.toml": _version_from_toml(
            os.path.join(REPO, "bindings", "acdp-node", "Cargo.toml")
        ),
        "acdp-node/package.json": _version_from_json(
            os.path.join(REPO, "bindings", "acdp-node", "package.json")
        ),
    }
    assert len(set(versions.values())) == 1, (
        f"binding versions out of sync: {versions}"
    )


def test_node_reported_version_matches_package(node):
    pkg_version = _version_from_json(
        os.path.join(REPO, "bindings", "acdp-node", "package.json")
    )
    assert node.call("describe")["version"] == pkg_version


if __name__ == "__main__":  # convenience: `python test_parity.py`
    sys.exit(pytest.main([__file__, "-v"]))
