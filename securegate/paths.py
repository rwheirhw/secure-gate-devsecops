"""Filesystem layout for an installed SecureGate app.

Workspace paths (reports, baselines, project policy, local manifests) are
relative to the current working directory or SECUREGATE_HOME. Bundled
dashboard files, default policy, and sample manifests ship inside the
package so the app works after ``pip install`` without the git checkout.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path


def workspace_root() -> Path:
    """Directory used for project files (config, reports, baselines, k8s)."""

    home = os.environ.get("SECUREGATE_HOME")
    if home:
        return Path(home).expanduser().resolve()
    return Path.cwd()


def reports_dir() -> Path:
    return workspace_root() / "reports"


def baselines_dir() -> Path:
    return workspace_root() / "baselines"


def packaged_file(*relative: str) -> Path:
    """Return a filesystem path to a file shipped with the package."""

    return Path(str(files("securegate").joinpath(*relative)))


def web_dir() -> Path:
    return packaged_file("web")


def packaged_policy() -> Path:
    yaml_path = packaged_file("data", "policy.yaml")
    if yaml_path.is_file():
        return yaml_path
    return packaged_file("data", "policy.json")


def resolve_workspace_file(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return workspace_root() / candidate


def resolve_policy(policy: Path | str | None = None) -> Path:
    """Locate a policy file for CLI and API use.

    Search order:
    1. Explicit ``--policy`` / request path (as given, then vs workspace)
    2. ``SECUREGATE_POLICY``
    3. ``config/policy.yaml`` then ``config/policy.json`` in the workspace
    4. Packaged default policy
    """

    candidates: list[Path] = []

    if policy is not None:
        given = Path(policy)
        candidates.append(given)
        if not given.is_absolute():
            candidates.append(workspace_root() / given)

    env_policy = os.environ.get("SECUREGATE_POLICY")
    if env_policy:
        candidates.append(Path(env_policy).expanduser())

    root = workspace_root()
    candidates.extend(
        [
            root / "config" / "policy.yaml",
            root / "config" / "policy.json",
        ]
    )
    candidates.append(packaged_policy())

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file():
            return resolved

    raise FileNotFoundError(
        "No SecureGate policy file found. Pass --policy, set "
        "SECUREGATE_POLICY, or add config/policy.yaml to the workspace."
    )


def load_sample_manifests() -> dict[str, str]:
    """Sample YAML for the dashboard workbench (workspace first, then package)."""

    mapping = {
        "enterprise_sample": (
            "k8s/enterprise-sample.yaml",
            "enterprise-sample.yaml",
        ),
        "hardened_sample": (
            "k8s/deployment.yaml",
            "deployment.yaml",
        ),
        "insecure_sample": (
            "k8s/insecure-sample.yaml",
            "insecure-sample.yaml",
        ),
    }
    samples: dict[str, str] = {}
    root = workspace_root()
    for name, (rel_workspace, packaged_name) in mapping.items():
        workspace_path = root / rel_workspace
        if workspace_path.is_file():
            samples[name] = workspace_path.read_text(encoding="utf-8")
            continue
        packaged = packaged_file("data", "samples", packaged_name)
        if packaged.is_file():
            samples[name] = packaged.read_text(encoding="utf-8")
    return samples
