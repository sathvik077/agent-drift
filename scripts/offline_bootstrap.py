#!/usr/bin/env python3
"""Reconstruct an offline wheelhouse and Node package tree when registries are blocked.

Why this exists: on the machine where Agent Drift was built, ``pypi.org`` and
``registry.npmjs.org` both answer HTTP 403 at the egress proxy, so neither ``uv pip
install`` nor ``npm ci`` can resolve anything. The host nevertheless carries a usable
local cache. This script turns that cache into a real wheelhouse so that
``uv pip install --no-index --find-links`` works, and links the pinned Node packages
from a local store.

``make setup`` tries the network first and only falls back to this script, so a normal
machine with registry access never uses it. It is not a vendoring strategy for the
published project -- it is an escape hatch for restricted environments, and the exact
versions it produces are the ones recorded in ``pyproject.toml``.

Usage:
    python scripts/offline_bootstrap.py --python        # build .wheelhouse/
    python scripts/offline_bootstrap.py --node          # link node_modules
    python scripts/offline_bootstrap.py --python --node
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WHEELHOUSE = REPO_ROOT / ".wheelhouse"

#: Directories that may contain extracted wheel trees (``<name>-<version>.dist-info``).
UV_ARCHIVE_CANDIDATES = (
    Path(os.environ.get("UV_CACHE_DIR", "")) / "archive-v0" if os.environ.get("UV_CACHE_DIR") else None,
    Path.home() / ".cache" / "uv" / "archive-v0",
    Path("/root/.cache/uv/archive-v0"),
)

#: Local Node package stores searched for the pinned frontend packages.
NODE_STORE_CANDIDATES = (
    Path("/opt/npm-tools/node_modules"),
    Path("/usr/lib/node_modules"),
    Path.home() / ".npm-global" / "lib" / "node_modules",
)

NODE_PACKAGES = ("react", "react-dom", "typescript", "esbuild", "scheduler")


#: Preference order for wheel tags when a WHEEL file declares several.
def _best_tag(tags: list[str]) -> str:
    for tag in tags:
        if tag.startswith(("cp3", "py3")):
            return tag
    return tags[0] if tags else "py3-none-any"


def _read_tags(wheel_meta: Path) -> list[str]:
    tags: list[str] = []
    try:
        for line in wheel_meta.read_text(errors="replace").splitlines():
            if line.lower().startswith("tag:"):
                tags.append(line.split(":", 1)[1].strip())
    except OSError:
        pass
    return tags


def build_wheelhouse() -> int:
    """Repack extracted wheel trees from a local uv cache into real .whl files."""
    sources = [p for p in UV_ARCHIVE_CANDIDATES if p is not None and p.is_dir()]
    if not sources:
        print("offline_bootstrap: no local uv archive cache found; nothing to do", file=sys.stderr)
        return 1

    WHEELHOUSE.mkdir(parents=True, exist_ok=True)
    made = 0
    for source in sources:
        for entry in sorted(source.iterdir()):
            if not entry.is_dir():
                continue
            dist_infos = [d for d in entry.iterdir() if d.is_dir() and d.name.endswith(".dist-info")]
            if len(dist_infos) != 1:
                continue
            stem = dist_infos[0].name.removesuffix(".dist-info")
            if "-" not in stem:
                continue
            name, version = stem.rsplit("-", 1)
            tag = _best_tag(_read_tags(dist_infos[0] / "WHEEL"))
            target = WHEELHOUSE / f"{name}-{version}-{tag}.whl"
            if target.exists():
                continue
            try:
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                    for root, _dirs, files in os.walk(entry):
                        for filename in files:
                            full = Path(root) / filename
                            archive.write(full, str(full.relative_to(entry)))
                made += 1
            except OSError as exc:
                print(f"offline_bootstrap: failed to pack {name}=={version}: {exc}", file=sys.stderr)
                target.unlink(missing_ok=True)

    total = len(list(WHEELHOUSE.glob("*.whl")))
    print(f"offline_bootstrap: wheelhouse at {WHEELHOUSE} now holds {total} wheels ({made} new)")
    return 0 if total else 1


def link_node_packages() -> int:
    """Link the pinned frontend packages from a local Node store into node_modules."""
    store = next((p for p in NODE_STORE_CANDIDATES if p.is_dir()), None)
    if store is None:
        print("offline_bootstrap: no local node package store found", file=sys.stderr)
        return 1

    target_root = REPO_ROOT / "apps" / "dashboard" / "node_modules"
    target_root.mkdir(parents=True, exist_ok=True)
    linked: list[str] = []
    missing: list[str] = []
    for package in NODE_PACKAGES:
        source = store / package
        if not source.is_dir():
            missing.append(package)
            continue
        destination = target_root / package
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink():
                destination.unlink()
            else:
                shutil.rmtree(destination)
        destination.symlink_to(source, target_is_directory=True)
        linked.append(package)

    # esbuild's platform binary lives in a scoped package; link whatever is present.
    scoped = store / "@esbuild"
    if scoped.is_dir():
        scoped_target = target_root / "@esbuild"
        if scoped_target.is_symlink():
            scoped_target.unlink()
        elif scoped_target.exists():
            shutil.rmtree(scoped_target)
        scoped_target.symlink_to(scoped, target_is_directory=True)
        linked.append("@esbuild")

    bin_dir = target_root / ".bin"
    bin_dir.mkdir(exist_ok=True)
    for tool, relative in (("esbuild", "esbuild/bin/esbuild"), ("tsc", "typescript/bin/tsc")):
        source = store / relative
        if source.exists():
            link = bin_dir / tool
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(source)

    print(f"offline_bootstrap: linked {', '.join(linked)} from {store} into {target_root}")
    if missing:
        print(f"offline_bootstrap: NOT FOUND in local store: {', '.join(missing)}", file=sys.stderr)
    return 0 if linked else 1


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", action="store_true", help="build the Python wheelhouse")
    parser.add_argument("--node", action="store_true", help="link Node packages")
    args = parser.parse_args()
    if not (args.python or args.node):
        parser.error("choose --python, --node, or both")

    status = 0
    if args.python:
        status |= build_wheelhouse()
    if args.node:
        status |= link_node_packages()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
