"""Local content-addressed capture storage and transactional assessment import."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from .capture_analysis import analyze_capture_file, capture_size_limit_bytes, scoped_capture_result


def import_capture(source, captures_dir, store, assessment_id, wireless_scope, progress=None):
    """Copy, validate, analyze, and persist a capture without exposing its source path."""
    source = Path(source).resolve(strict=True)
    captures_dir = Path(captures_dir)
    if source.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Choose a .pcap or .pcapng capture file.")
    if not source.is_file():
        raise ValueError("Selected capture is not a regular file.")
    try:
        source_size = source.stat().st_size
    except OSError:
        raise ValueError("Selected capture could not be read.") from None
    if not source_size:
        raise ValueError("Capture file is empty.")
    size_limit = capture_size_limit_bytes()
    if source_size > size_limit:
        raise ValueError(f"Capture exceeds the {size_limit // (1024 * 1024)} MiB offline-analysis limit.")

    if captures_dir.is_symlink():
        raise ValueError("Capture storage directory must not be a symbolic link.")
    captures_dir.mkdir(parents=True, exist_ok=True)
    staging_dir = captures_dir / ".staging"
    staging_dir.mkdir(mode=0o700, exist_ok=True)
    if staging_dir.is_symlink():
        raise ValueError("Capture staging directory must not be a symbolic link.")
    try:
        os.chmod(captures_dir, 0o700)
        os.chmod(staging_dir, 0o700)
    except OSError:
        pass

    fd, stage_name = tempfile.mkstemp(prefix="capture-", suffix=source.suffix.lower(), dir=staging_dir)
    staged_path = Path(stage_name)
    copied = 0
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as destination, source.open("rb") as origin:
            while True:
                chunk = origin.read(1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > size_limit:
                    raise ValueError(f"Capture exceeds the {size_limit // (1024 * 1024)} MiB offline-analysis limit.")
                digest.update(chunk)
                destination.write(chunk)
                if progress:
                    progress({"stage": "copying", "bytes_copied": copied, "bytes_total": source_size})
            destination.flush()
            os.fsync(destination.fileno())
        if copied != source_size:
            raise ValueError("Capture changed while it was being copied; select it again and retry.")

        result = analyze_capture_file(staged_path, progress=progress)
        if result["sha256"] != digest.hexdigest():
            raise ValueError("Capture copy changed during validation; no evidence was retained.")
        result["filename"] = source.name
        result["source"] = "local_user_selected_capture"
        for field in ("deauthentication", "disassociation"):
            for frame in (result.get("management_frame_observations") or {}).get(field, []):
                frame["source_capture"] = source.name
        result = scoped_capture_result(result, wireless_scope)
        suffix = ".pcapng" if result["capture_format"] == "pcapng" else ".pcap"
        stored_filename = f"{result['sha256']}{suffix}"
        destination_path = captures_dir / stored_filename
        created_file = False
        if destination_path.is_symlink():
            raise ValueError("Existing content-addressed capture path is a symbolic link; import was stopped.")
        if destination_path.exists():
            existing_digest = hashlib.sha256()
            with destination_path.open("rb") as existing:
                for chunk in iter(lambda: existing.read(1024 * 1024), b""):
                    existing_digest.update(chunk)
            existing_hash = existing_digest.hexdigest()
            if existing_hash != result["sha256"]:
                raise ValueError("Content-addressed capture storage has a hash collision; import was stopped.")
        else:
            try:
                os.link(staged_path, destination_path)
                created_file = True
            except FileExistsError:
                if destination_path.is_symlink():
                    raise ValueError("Existing content-addressed capture path is a symbolic link; import was stopped.")
                existing_digest = hashlib.sha256()
                with destination_path.open("rb") as existing:
                    for chunk in iter(lambda: existing.read(1024 * 1024), b""):
                        existing_digest.update(chunk)
                if existing_digest.hexdigest() != result["sha256"]:
                    raise ValueError("Content-addressed capture storage has a hash collision; import was stopped.")
            except OSError:
                # Filesystems without hard-link support use exclusive creation,
                # which still refuses to replace existing evidence.
                try:
                    output_fd = os.open(destination_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    raise ValueError("Capture file was created concurrently; select it again and retry.") from None
                try:
                    with os.fdopen(output_fd, "wb") as output, staged_path.open("rb") as staged:
                        for chunk in iter(lambda: staged.read(1024 * 1024), b""):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    created_file = True
                except Exception:
                    try:
                        destination_path.unlink()
                    except OSError:
                        pass
                    raise
            if created_file:
                try:
                    staged_path.unlink()
                except OSError:
                    pass
            try:
                os.chmod(destination_path, 0o600)
            except OSError:
                pass

        relative_path = f"captures/{stored_filename}"
        try:
            saved = store.save_capture_analysis(assessment_id, result, relative_path)
        except Exception:
            if created_file:
                try:
                    destination_path.unlink()
                except OSError:
                    pass
            raise
        if progress:
            progress({"stage": "complete", "packets_examined": result.get("packets_examined", 0)})
        return {"result": result, "stored_path": relative_path, **saved}
    finally:
        try:
            staged_path.unlink()
        except FileNotFoundError:
            pass
