"""Safe, bounded local storage for engagement authorization documents."""
from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import uuid
from pathlib import Path

MAX_AUTHORIZATION_DOCUMENT_BYTES = 20 * 1024 * 1024
SUPPORTED_AUTHORIZATION_SUFFIXES = {".pdf", ".doc", ".docx", ".txt"}
_ASSESSMENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


def copy_authorization_document(source, storage_root, assessment_id, max_bytes=MAX_AUTHORIZATION_DOCUMENT_BYTES):
    """Copy one selected document into private local storage and return provenance only."""
    source = Path(source)
    storage_root = Path(storage_root)
    assessment_id = str(assessment_id or "")
    if not _ASSESSMENT_ID.fullmatch(assessment_id):
        raise ValueError("Invalid assessment identifier.")
    if source.suffix.lower() not in SUPPORTED_AUTHORIZATION_SUFFIXES:
        raise ValueError("Choose a supported authorization-document file: PDF, DOC, DOCX, or TXT.")
    if source.is_symlink():
        raise ValueError("Symbolic links are not accepted for authorization documents.")
    if storage_root.exists() and storage_root.is_symlink():
        raise ValueError("Authorization document storage must not be a symbolic link.")
    max_bytes = max(1, min(int(max_bytes), MAX_AUTHORIZATION_DOCUMENT_BYTES))
    try:
        source_fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ValueError("Selected authorization document could not be opened safely.") from None
    stage_path = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("Choose a regular authorization-document file.")
        if source_stat.st_size <= 0:
            raise ValueError("Authorization document is empty.")
        if source_stat.st_size > max_bytes:
            raise ValueError(f"Authorization document exceeds the {max_bytes // (1024 * 1024)} MiB size limit.")

        root = storage_root.resolve()
        directory = root / assessment_id
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.resolve().is_relative_to(root):
            raise ValueError("Authorization document path escaped its storage root.")
        try:
            os.chmod(root, 0o700)
            os.chmod(directory, 0o700)
        except OSError:
            pass

        suffix = source.suffix.lower()
        stored_name = f"{uuid.uuid4().hex}{suffix}"
        destination = directory / stored_name
        output_fd, stage_name = tempfile.mkstemp(prefix="authorization-", suffix=".staging", dir=directory)
        stage_path = Path(stage_name)
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(source_fd, "rb", closefd=True) as origin, os.fdopen(output_fd, "wb") as target:
            source_fd = -1
            while True:
                chunk = origin.read(1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise ValueError(f"Authorization document exceeds the {max_bytes // (1024 * 1024)} MiB size limit.")
                digest.update(chunk)
                target.write(chunk)
            if copied != source_stat.st_size or os.fstat(origin.fileno()).st_size != source_stat.st_size:
                raise ValueError("Authorization document changed while it was being copied.")
            target.flush()
            os.fsync(target.fileno())
        os.replace(stage_path, destination)
        stage_path = None
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        return {"filename": source.name, "stored_path": f"{assessment_id}/{stored_name}",
                "sha256": digest.hexdigest(), "size_bytes": copied,
                "document_format": suffix.lstrip(".").upper()}
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if stage_path is not None:
            try: stage_path.unlink()
            except OSError: pass


def delete_authorization_document(storage_root, stored_path):
    """Remove one app-owned copy only after verifying its path stays under storage_root."""
    root = Path(storage_root)
    relative = Path(str(stored_path or ""))
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Authorization document path is outside the document storage root.")
    if root.exists() and root.is_symlink():
        raise ValueError("Authorization document storage must not be a symbolic link.")
    root = root.resolve(strict=True)
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return False
    if not resolved.is_relative_to(root) or candidate.is_symlink() or not resolved.is_file():
        raise ValueError("Authorization document path is outside the document storage root.")
    resolved.unlink()
    try:
        resolved.parent.rmdir()
    except OSError:
        pass
    return True
