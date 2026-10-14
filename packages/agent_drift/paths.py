"""Sandbox path canonicalization.

This module answers one question: *does this argument refer to a resource inside the
sandbox root, and which scope does it fall under?* It is deliberately conservative --
every ambiguity is a rejection -- because the alternative is a traversal bug.

What it defends against, each with a test in ``tests/security/test_path_traversal.py``:

* ``..`` segments, including after URL-decoding and after unicode normalization
* absolute paths (POSIX ``/etc/passwd``, Windows ``C:\\``, UNC ``\\\\server\\share``)
* backslash separators used to smuggle a segment past a ``/``-only check
* null bytes and control characters
* symlinks whose target leaves the root (checked against the *resolved* real path)
* unicode confusables for ``.`` and ``/`` (fullwidth, ideographic) and zero-width joiners
* paths that normalize to the root itself or to empty

**Stated limitation.** For *controlled fixture tools* this is enforcement: the fixture
re-validates with :func:`resolve_in_root` at the moment it touches the filesystem, so
there is no window between check and use. For *arbitrary third-party tools* an
argument-level check cannot guarantee the tool honours it -- the tool may construct its
own path, follow a symlink we never saw, or ignore the argument entirely. That TOCTOU
caveat is in ``docs/THREAT_MODEL.md`` and the README, and it is a property of
argument-level interposition, not a bug here.
"""

from __future__ import annotations

import errno
import os
import re
import unicodedata
import urllib.parse
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Final, NamedTuple

__all__ = [
    "PathVerdict",
    "matches_scope",
    "normalize_relative_path",
    "resolve_in_root",
    "scope_for",
]

#: Characters that must never appear in a sandbox path argument.
_FORBIDDEN_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")

#: Unicode code points that look like a dot or a separator and are rejected outright.
_CONFUSABLES: Final[dict[str, str]] = {
    "\uff0e": ".",  # FULLWIDTH FULL STOP
    "\u3002": ".",  # IDEOGRAPHIC FULL STOP
    "\uff0f": "/",  # FULLWIDTH SOLIDUS
    "\uff3c": "\\",  # FULLWIDTH REVERSE SOLIDUS
    "\u2215": "/",  # DIVISION SLASH
    "\u29f8": "/",  # BIG SOLIDUS
}

#: Zero-width and bidi control characters that could hide a traversal segment.
_INVISIBLE: Final[tuple[str, ...]] = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
)


class PathVerdict(NamedTuple):
    """Outcome of normalizing a path argument.

    ``ok`` false means the path is rejected and ``reason`` names why, using a
    :class:`agent_drift.reasons.Reason` value. ``normalized`` is only meaningful when
    ``ok`` is true.
    """

    ok: bool
    normalized: str
    reason: str | None = None
    detail: str | None = None


def _decode_repeatedly(text: str, *, rounds: int = 3) -> str:
    """URL-decode up to ``rounds`` times so ``%252e%252e`` cannot hide a ``..``.

    Bounded because unbounded decoding is itself a denial-of-service shape. Three rounds
    covers double and triple encoding, which is past the point of plausible legitimate use.
    """
    current = text
    for _ in range(rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            return current
        current = decoded
    return current


def normalize_relative_path(raw: str) -> PathVerdict:
    """Normalize an untrusted path argument to a safe sandbox-relative POSIX path.

    Returns a :class:`PathVerdict`. The returned ``normalized`` value, when ``ok``, has
    no ``.`` or ``..`` segments, uses ``/`` separators only, has no leading slash, and is
    NFC-normalized.
    """
    from .reasons import Reason

    if not isinstance(raw, str):
        return PathVerdict(False, "", Reason.RESOURCE_MISSING, "path argument was not a string")
    if raw == "":
        return PathVerdict(False, "", Reason.RESOURCE_MISSING, "path argument was empty")

    # 1. Reject invisible characters before any other processing.
    for ch in _INVISIBLE:
        if ch in raw:
            return PathVerdict(
                False,
                "",
                Reason.PATH_UNSAFE_ENCODING,
                f"path contains invisible character U+{ord(ch):04X}",
            )

    # 2. Decode percent-encoding, then require the result to already be NFC.
    #
    #    Normalizing silently would make two *distinct* filesystem paths -- NFC and NFD
    #    spellings of the same visible name -- indistinguishable to the policy and to an
    #    approval's argument digest, while a tool that does not normalize would act on the
    #    other one. An independent review demonstrated exactly that: a human approved
    #    "cafe\u0301.txt" and a different file, "caf\u00e9.txt", was deleted. Rejecting a
    #    non-NFC path keeps "what was checked", "what the reviewer saw" and "what the tool
    #    receives" the same bytes.
    decoded = _decode_repeatedly(raw)
    text = unicodedata.normalize("NFC", decoded)
    if text != decoded:
        return PathVerdict(
            False,
            "",
            Reason.PATH_UNSAFE_ENCODING,
            "path is not in Unicode NFC form; two spellings of one visible name would be "
            "distinct files on disk but identical after normalization, so the ambiguous "
            "spelling is refused rather than silently rewritten",
        )

    # 3. Reject control characters and null bytes.
    if _FORBIDDEN_CHARS.search(text):
        return PathVerdict(
            False,
            "",
            Reason.PATH_UNSAFE_ENCODING,
            "path contains a null byte or control character",
        )

    # 4. Reject separator and dot confusables rather than folding them: a legitimate
    #    filename has no business containing a fullwidth solidus.
    for confusable, plain in _CONFUSABLES.items():
        if confusable in text:
            return PathVerdict(
                False,
                "",
                Reason.PATH_UNSAFE_ENCODING,
                f"path contains unicode confusable U+{ord(confusable):04X} for {plain!r}",
            )

    # 5. Reject Windows drive letters and UNC paths before separator folding.
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith("\\\\"):
        return PathVerdict(False, "", Reason.PATH_ABSOLUTE, "path was an absolute Windows or UNC path")

    # 6. Fold backslashes to forward slashes so a single traversal check covers both.
    text = text.replace("\\", "/")

    # 7. Reject absolute POSIX paths.
    if text.startswith("/"):
        return PathVerdict(False, "", Reason.PATH_ABSOLUTE, "path was absolute")

    # 8. Collapse ``.`` and ``..`` segments, rejecting only a path that actually climbs
    #    above the root. ``docs/../docs/README.md`` is a legitimate if redundant spelling
    #    of ``docs/README.md`` and rejecting it was a false block the evaluation suite
    #    caught; ``docs/../../private/x`` genuinely escapes and is rejected. Segment-wise
    #    comparison means a filename that merely contains dots (``..hidden``, ``a..b``)
    #    is untouched.
    #
    #    Lexical collapsing is not sufficient on its own when a component is a symlink
    #    (``a/link/../b`` can resolve elsewhere), which is why :func:`resolve_in_root`
    #    re-resolves through the real filesystem whenever a sandbox root is configured,
    #    and why the fixture tools re-validate at the moment of use.
    parts: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                return PathVerdict(
                    False,
                    "",
                    Reason.PATH_TRAVERSAL,
                    "path climbed above the sandbox root with a '..' segment",
                )
            parts.pop()
            continue
        parts.append(segment)

    if not parts:
        return PathVerdict(False, "", Reason.RESOURCE_MISSING, "path normalized to the sandbox root")

    normalized = str(PurePosixPath(*parts))

    # 9. Defence in depth: the normalized form must still be relative and traversal-free.
    if normalized.startswith("/") or ".." in PurePosixPath(normalized).parts:
        return PathVerdict(False, "", Reason.PATH_TRAVERSAL, "normalized path was still unsafe")

    return PathVerdict(True, normalized)


def resolve_in_root(root: Path, relative: str) -> PathVerdict:
    """Resolve ``relative`` under ``root`` and confirm the real path stays inside.

    This is the check that catches symlink escapes, because it compares the *resolved*
    path -- following every link -- against the resolved root. Called both by the policy
    engine (on the argument) and by the fixture tools (at the moment of use), which is
    what closes the TOCTOU window for tools we control.
    """
    from .reasons import Reason

    verdict = normalize_relative_path(relative)
    if not verdict.ok:
        return verdict

    try:
        root_real = root.resolve(strict=True) if root.exists() else root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        return PathVerdict(
            False, "", Reason.PATH_SYMLINK_ESCAPE, f"sandbox root could not be resolved: {exc}"
        )

    # Resolve the deepest *existing* ancestor strictly, so a symlink loop surfaces as
    # ELOOP instead of being silently returned unresolved by ``strict=False``. A path
    # whose tail does not exist yet is legitimate -- creating a new file is a normal
    # write -- so only the existing prefix is resolved strictly, and the remaining
    # components are appended and re-checked for traversal.
    segments = PurePosixPath(verdict.normalized).parts
    resolved = root_real
    try:
        for index, segment in enumerate(segments):
            nxt = resolved / segment
            if nxt.exists() or nxt.is_symlink():
                resolved = nxt.resolve(strict=True)
            else:
                remainder = segments[index:]
                if any(part == ".." for part in remainder):
                    return PathVerdict(False, "", Reason.PATH_TRAVERSAL, "unresolved tail contained '..'")
                resolved = resolved.joinpath(*remainder)
                break
    except RuntimeError as exc:  # pathlib raises RuntimeError on a detected loop
        return PathVerdict(False, "", Reason.PATH_SYMLINK_ESCAPE, f"symlink loop: {exc}")
    except OSError as exc:
        if getattr(exc, "errno", None) in (errno.ELOOP, errno.ENAMETOOLONG):
            return PathVerdict(False, "", Reason.PATH_SYMLINK_ESCAPE, f"symlink loop or name too long: {exc}")
        return PathVerdict(False, "", Reason.PATH_SYMLINK_ESCAPE, f"path could not be resolved: {exc}")

    candidate = resolved

    if candidate != root_real and not candidate.is_relative_to(root_real):
        return PathVerdict(
            False,
            "",
            Reason.PATH_SYMLINK_ESCAPE,
            "resolved path escaped the sandbox root (symlink or traversal)",
        )
    if candidate == root_real:
        return PathVerdict(False, "", Reason.RESOURCE_MISSING, "path resolved to the sandbox root itself")

    return PathVerdict(True, str(candidate.relative_to(root_real)).replace(os.sep, "/"))


def matches_scope(normalized_path: str, scope: str) -> bool:
    """Does a normalized path fall under a single contract scope pattern?

    Scopes use shell-glob syntax with one extension: a trailing ``/**`` matches the
    directory's entire subtree at any depth, which ``fnmatch`` alone does not do because
    its ``*`` crosses separators and its ``**`` is not special. A scope without a glob
    is treated as an exact path or a directory prefix.
    """
    path = normalized_path.strip("/")
    pattern = scope.strip()
    if not pattern:
        return False
    pattern = pattern.replace("\\", "/").strip("/")

    if pattern.endswith("/**"):
        prefix = pattern[:-3].strip("/")
        if not prefix:
            return True
        return path == prefix or path.startswith(prefix + "/")

    if pattern == "**":
        return True

    if any(ch in pattern for ch in "*?["):
        # fnmatch's '*' crosses '/', which would make 'docs/*' match 'docs/a/b'.
        # Compare segment counts to keep a single-star scope single-level.
        if fnmatch(path, pattern):
            if "**" in pattern:
                return True
            return path.count("/") == pattern.count("/")
        return False

    return path == pattern or path.startswith(pattern.rstrip("/") + "/")


def scope_for(normalized_path: str, scopes: list[str]) -> str | None:
    """Return the first scope that admits ``normalized_path``, or ``None``.

    The matching scope is recorded in the decision's evidence so a reviewer can see
    *which* clause authorized a resource, not merely that something did.
    """
    for scope in scopes:
        if matches_scope(normalized_path, scope):
            return scope
    return None
