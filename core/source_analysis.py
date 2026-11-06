"""Bounded, non-executing source inspection for authorized code review.

This module reports deterministic review indicators. It never treats a regex
match as proof of exploitability and never returns a matched secret literal.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path
from pathlib import PurePath

MAX_FILE_BYTES = 2 * 1024 * 1024
SUPPORTED_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go", ".rs",
    ".php", ".rb", ".sql", ".html", ".htm", ".xml", ".json", ".toml", ".yaml",
    ".yml", ".ini", ".cfg", ".conf", ".sh", ".env", ".properties", ".txt",
}

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>\b(?:api[_-]?key|client[_-]?secret|secret|access[_-]?token|password|passwd|private[_-]?key)\b"
    r"\s*[:=]\s*)(?P<quote>['\"]?)(?P<value>[^\s'\"#;,}]{8,})(?P=quote)"
)

_RULES = (
    ("PY-DYNAMIC-EVAL", ".py", re.compile(r"\beval\s*\("), "Dynamic evaluation call requires review", "Review whether untrusted input can reach this dynamic evaluation call."),
    ("PY-DYNAMIC-EXEC", ".py", re.compile(r"\bexec\s*\("), "Dynamic execution call requires review", "Review whether untrusted input can reach this dynamic execution call."),
    ("PY-PICKLE-LOAD", ".py", re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\("), "Python pickle deserialization requires review", "Only deserialize trusted, integrity-protected pickle data; prefer a safe data format."),
    ("PY-YAML-UNSAFE-LOAD", ".py", re.compile(r"\byaml\.load\s*\("), "YAML loader call requires review", "Verify the loader uses a safe loader and does not construct arbitrary Python objects."),
    ("JS-DYNAMIC-CODE", ".js", re.compile(r"\bnew\s+Function\s*\("), "Dynamic JavaScript code construction requires review", "Avoid constructing executable code from data; use explicit functions and validated inputs."),
)


_WITHHELD = "Source text withheld; raw code and credential values are never included in results."
MAX_REPOSITORY_FILES = 500
MAX_REPOSITORY_BYTES = 25 * 1024 * 1024
_SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "vendor", "dist", "build",
    "coverage", "__pycache__", ".next", ".nuxt", ".idea", ".pytest_cache", ".mypy_cache", ".tox",
}
_SKIP_FILES = {".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "credentials", "secrets"}
_DEPENDENCY_MANIFESTS = {"requirements.txt", "pyproject.toml", "package.json", "cargo.toml", "go.mod", "gemfile", "composer.json"}
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9.*+^~=<>! _,-]{0,80}$")


def analyze_files(files):
    """Analyze an iterable of ``{path, content}`` records without executing it.

    Inputs above 2 MiB and unsupported file types are skipped. Output includes
    content hashes and line references but never includes secret literal values.
    """
    analyzed = []
    skipped = []
    indicators = []
    for item in list(files or [])[:MAX_REPOSITORY_FILES]:
        path = str((item or {}).get("path") or "unknown")
        content = (item or {}).get("content")
        suffix = PurePath(path).suffix.lower()
        if suffix not in SUPPORTED_SUFFIXES:
            skipped.append({"path": PurePath(path).name, "reason": "Unsupported source/configuration file type."})
            continue
        if not isinstance(content, str):
            skipped.append({"path": PurePath(path).name, "reason": "File could not be decoded as UTF-8 text."})
            continue
        encoded = content.encode("utf-8", errors="replace")
        if len(encoded) > MAX_FILE_BYTES:
            skipped.append({"path": PurePath(path).name, "reason": "File exceeds the 2 MiB per-file analysis limit."})
            continue
        digest = hashlib.sha256(encoded).hexdigest()
        name = PurePath(path).name[:255] or "source"
        analyzed.append({"path": name, "size_bytes": len(encoded), "sha256": digest})
        for line_number, line in enumerate(content.splitlines(), 1):
            for match in _SECRET_ASSIGNMENT.finditer(line):
                indicators.append({
                    "rule_id": "SOURCE-SECRET-LITERAL", "title": "Potential hard-coded credential literal",
                    "severity": "High", "confidence": "Medium", "path": name, "line": line_number,
                    "excerpt": _WITHHELD,
                    "description": "A credential-like assignment contains a non-empty literal. This pattern is a review lead and may include a placeholder or non-secret value.",
                    "recommendation": "Remove the literal, rotate it if it was active, and load secrets from a protected runtime secret store.",
                })
            for rule_id, extension, pattern, title, recommendation in _RULES:
                if suffix == extension and pattern.search(line):
                    indicators.append({
                        "rule_id": rule_id, "title": title, "severity": "Medium", "confidence": "Observed",
                        "path": name, "line": line_number, "excerpt": _WITHHELD,
                        "description": "A source pattern matched. The match alone does not establish reachable input or exploitability.",
                        "recommendation": recommendation,
                    })
    return {
        "scanner": "WiFiSentinel static source review",
        "scanner_version": 1,
        "execution": "read_only_no_code_execution",
        "files_analyzed": len(analyzed),
        "files": analyzed,
        "skipped": skipped,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "limitations": [
            "Pattern matches are review indicators, not proof of exploitability.",
            "No code was executed and no dependency advisory database was queried.",
            "Selected files are analyzed individually; unselected repository files are not covered.",
        ],
    }


def _safe_relative_file(root, path):
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    parts = [part.casefold() for part in relative.parts]
    name = relative.name.casefold()
    if any(part in _SKIP_DIRECTORIES for part in parts[:-1]):
        return None
    if name in _SKIP_FILES or name.startswith(".env") or any(token in name for token in ("secret", "credential")):
        return None
    if path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der"}:
        return None
    return relative


def _dependency_records(manifest_name, text):
    records = []
    try:
        if manifest_name == "package.json":
            value = json.loads(text)
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                entries = value.get(section, {}) if isinstance(value, dict) else {}
                if isinstance(entries, dict):
                    records.extend((name, version, section) for name, version in entries.items())
        elif manifest_name == "pyproject.toml":
            value = tomllib.loads(text)
            project = value.get("project", {})
            dependencies = project.get("dependencies", []) if isinstance(project, dict) else []
            for item in dependencies if isinstance(dependencies, list) else []:
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(.*)", str(item))
                if match:
                    records.append((match.group(1), match.group(2), "project.dependencies"))
            optional = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
            if isinstance(optional, dict):
                for group, entries in optional.items():
                    for item in entries if isinstance(entries, list) else []:
                        match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(.*)", str(item))
                        if match:
                            records.append((match.group(1), match.group(2), f"optional:{group}"))
        elif manifest_name == "requirements.txt":
            for line in text.splitlines():
                line = line.partition("#")[0].strip()
                if not line or line.startswith(("-", "git+", "http:", "https:")):
                    continue
                match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.*)$", line)
                if match:
                    records.append((match.group(1), match.group(2), "requirements"))
        elif manifest_name == "cargo.toml":
            value = tomllib.loads(text)
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                entries = value.get(section, {})
                if isinstance(entries, dict):
                    for name, spec in entries.items():
                        version = spec.get("version", "") if isinstance(spec, dict) else spec
                        records.append((name, version, section))
        elif manifest_name == "go.mod":
            in_require = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("require ("):
                    in_require = True
                    continue
                if in_require and stripped == ")":
                    in_require = False
                    continue
                if stripped.startswith("require "):
                    stripped = stripped[len("require "):]
                elif not in_require:
                    continue
                match = re.match(r"^([^\s]+)\s+(v[0-9][^\s]*)", stripped)
                if match:
                    records.append((match.group(1), match.group(2), "go.mod"))
        elif manifest_name == "gemfile":
            for match in re.finditer(r"(?m)^\s*gem\s+['\"]([A-Za-z0-9_.-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
                records.append((match.group(1), match.group(2) or "", "Gemfile"))
        elif manifest_name == "composer.json":
            value = json.loads(text)
            for section in ("require", "require-dev"):
                entries = value.get(section, {}) if isinstance(value, dict) else {}
                if isinstance(entries, dict):
                    records.extend((name, version, section) for name, version in entries.items()
                                   if name != "php")
    except (ValueError, TypeError, tomllib.TOMLDecodeError):
        return []

    clean = []
    for name, version, source in records[:500]:
        name = str(name).strip()[:160]
        version = str(version or "").strip()[:80]
        source = str(source)[:80]
        if name and _SAFE_VERSION.fullmatch(version):
            clean.append({"name": name, "version_constraint": version, "group": source,
                          "manifest": manifest_name})
    return clean


def analyze_repository(root_path):
    """Read a bounded repository tree without following symlinks or executing files."""
    supplied = Path(root_path).expanduser()
    if supplied.is_symlink():
        raise ValueError("Repository root must not be a symbolic link.")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Repository root is unavailable.") from exc
    if not root.is_dir():
        raise ValueError("Choose a repository directory.")

    files = []
    manifests = []
    dependencies = []
    skipped = []
    total_bytes = 0
    stop = False
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = [name for name in directories if name.casefold() not in _SKIP_DIRECTORIES
                          and not (current_path / name).is_symlink()]
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink():
                skipped.append({"path": path.relative_to(root).as_posix(), "reason": "Symbolic link not followed."})
                continue
            relative = _safe_relative_file(root, path)
            if relative is None:
                continue
            name = relative.name.casefold()
            is_manifest = name in _DEPENDENCY_MANIFESTS or name.startswith("requirements") and name.endswith(".txt")
            if path.suffix.casefold() not in SUPPORTED_SUFFIXES and not is_manifest:
                continue
            if len(files) >= MAX_REPOSITORY_FILES or total_bytes >= MAX_REPOSITORY_BYTES:
                stop = True
                break
            try:
                size = path.stat().st_size
            except OSError:
                skipped.append({"path": relative.as_posix(), "reason": "File metadata unavailable."})
                continue
            if size > MAX_FILE_BYTES:
                skipped.append({"path": relative.as_posix(), "reason": "File exceeds the 2 MiB per-file limit."})
                continue
            if total_bytes + size > MAX_REPOSITORY_BYTES:
                stop = True
                break
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                skipped.append({"path": relative.as_posix(), "reason": "File could not be safely read as UTF-8 text."})
                continue
            total_bytes += size
            files.append({"path": relative.as_posix(), "content": content})
            if is_manifest:
                manifests.append({"path": relative.as_posix(), "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()})
                dependencies.extend(_dependency_records(name, content))
        if stop:
            break

    result = analyze_files(files)
    result["scanner"] = "SOURCE-REPOSITORY-EVIDENCE · WiFiSentinel static repository review"
    result["repository_scope"] = "selected local directory"
    result["total_bytes_analyzed"] = total_bytes
    result["files"] = [{**record, "path": file_item["path"]}
                       for record, file_item in zip(result["files"], files)]
    result["manifests"] = manifests
    result["dependencies"] = dependencies[:2000]
    result["skipped"] = (result.get("skipped") or []) + skipped
    result["truncated_by_repository_limit"] = stop
    result["limitations"] = [
        "Repository review is static and read-only; no source, build script, or dependency was executed.",
        "Generated and common dependency trees, symbolic links, and secret-bearing files are excluded.",
        "Dependency versions are inventory only; no advisory database or network lookup is used.",
        "Pattern matches require manual data-flow and runtime-reachability review.",
        "At most 500 files and 25 MiB total are reviewed; individual files are capped at 2 MiB.",
    ]
    return result
