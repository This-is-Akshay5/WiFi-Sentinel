"""Research dataset analytics for the supplied association/disassociation corpus.

This corpus is *research evidence*. It is never merged into live telemetry, never
inserted into the device inventory, and every result it produces is tagged
``research`` so the UI can label it separately.

The file is ~145k rows, so the full pass is expensive. Results are cached per
process and the heavy analyses share a single parsed pass.
"""
from __future__ import annotations

import csv
import datetime as dt
import threading
from collections import Counter, defaultdict
from pathlib import Path

from .logging_setup import get_logger

log = get_logger("dataset")

TIMESTAMP_FORMAT = "%b %d, %Y @ %H:%M:%S.%f"
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_DISASSOCIATION_THRESHOLD = 10
DEFAULT_DISASSOCIATION_RATIO = 0.5
MAX_TABLE_ROWS = 500

LIMITATIONS = (
    "The corpus contains association/disassociation events only: timestamp, MAC, event type and a normal/attack label. "
    "It has no packet payloads, no SSIDs, no BSSIDs, no channels, no signal values and no hostnames.",
    "MAC addresses are anonymised study identifiers, not local network inventory, and cannot be resolved to a vendor or owner.",
    "The attack/normal label is supplied with the dataset; this application does not derive it and cannot validate it.",
    "Temporal analysis here is computed over the corpus only. It is not evidence about the operator's live network.",
    "Association/disassociation volume alone does not distinguish an attack from a legitimate roaming, reboot or power event.",
)


class DatasetEngine:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._summary = None
        self._analysis = None
        self._detections = {}
        self._available = None
        self._rows_cache = None
        self._source_signature = None
        self._total_rows = 0
        self._discarded_rows = 0
        self._schema_errors = []
        self._processed_at = None

    # ------------------------------------------------------------------ input
    @property
    def available(self):
        exists = self.path.is_file()
        if self._available != exists:
            self._available = exists
            self._summary = None
            self._analysis = None
            self._detections = {}
            self._rows_cache = None
            self._source_signature = None
        if not exists:
            log.warning("dataset_missing", extra={"context": {"path": str(self.path)}})
        return self._available

    def _rows(self):
        """Return valid parsed rows, cached for the current on-disk dataset version."""
        with self._lock:
            try:
                stat = self.path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                if self._source_signature is not None:
                    self._summary = None
                    self._analysis = None
                    self._detections = {}
                self._rows_cache = None
                self._source_signature = None
                self._available = False
                return iter(())
            if self._rows_cache is None or signature != self._source_signature:
                self._summary = None
                self._analysis = None
                self._detections = {}
                if self._source_signature is not None and signature != self._source_signature:
                    self._summary = None
                    self._analysis = None
                    self._detections = {}
                self._available = True
                parsed = []
                with self.path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                    reader = csv.DictReader(handle)
                    required = {"@timestamp", "mac_address", "association", "dataType"}
                    self._schema_errors = sorted(required - set(reader.fieldnames or []))
                    self._total_rows = 0
                    self._discarded_rows = 0
                    for row in reader:
                        self._total_rows += 1
                        try:
                            if self._schema_errors or None in row:
                                raise ValueError("Malformed or incompatible row")
                            stamp = dt.datetime.strptime(row["@timestamp"], TIMESTAMP_FORMAT)
                        except (ValueError, KeyError, TypeError):
                            self._discarded_rows += 1
                            continue
                        mac = (row.get("mac_address") or "").strip()
                        association = (row.get("association") or "").strip().lower()
                        label = (row.get("dataType") or "").strip().lower()
                        if mac and association in ("associated", "disassociated") and label in ("attack", "normal"):
                            parsed.append((stamp, mac, association, label))
                        else:
                            self._discarded_rows += 1
                self._rows_cache = tuple(parsed)
                self._source_signature = signature
                self._processed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            return iter(self._rows_cache)

    # ---------------------------------------------------------------- summary
    def summary(self):
        # Check the current file signature before returning a cached summary;
        # this also invalidates cached results when a missing file appears.
        self._rows()
        with self._lock:
            if self._summary is not None:
                return self._summary
        records = 0
        labels, associations, devices = Counter(), Counter(), Counter()
        first = last = None
        for stamp, mac, association, label in self._rows():
            records += 1
            labels[label] += 1
            associations[association] += 1
            devices[mac] += 1
            if first is None or stamp < first:
                first = stamp
            if last is None or stamp > last:
                last = stamp
        summary = {
            "available": self.available,
            "file": self.path.name,
            "records": records,
            "rows_seen": self._total_rows,
            "discarded_rows": self._discarded_rows,
            "schema_errors": list(self._schema_errors),
            "parsing_status": "missing" if not self.available else ("invalid_schema" if self._schema_errors else ("partial" if self._discarded_rows else "complete")),
            "last_processed_at": self._processed_at,
            "labels": dict(labels),
            "associations": dict(associations),
            "devices": len(devices),
            "events_by_device": dict(devices),
            "start": first.isoformat() if first else None,
            "end": last.isoformat() if last else None,
            "span_seconds": int((last - first).total_seconds()) if first and last else 0,
            "columns": ["@timestamp", "mac_address", "association", "dataType"],
            "limitations": list(LIMITATIONS),
        }
        with self._lock:
            self._summary = summary
        log.info("dataset_summary", extra={"context": {"records": records, "devices": len(devices)}})
        return summary

    # ---------------------------------------------------------------- analyze
    def analyze(self, device=None, window_seconds=DEFAULT_WINDOW_SECONDS, use_cache=True, full=False):
        """Per-device and per-window aggregates derived from the corpus.

        ``full=True`` disables the display row cap and is used by internal callers
        (such as :meth:`detection`) that must not silently analyse a truncated set.
        """
        if use_cache and not full:
            with self._lock:
                if self._analysis is not None:
                    return self._analysis
        if not self.available:
            return {"available": False, "summary": self.summary(), "windows": [], "devices": [], "temporal": [],
                    "limitations": list(LIMITATIONS),
                    "error": "Research dataset not present on disk. Place wifi_association_disassociation.csv in data/."}

        windows = defaultdict(lambda: {"events": 0, "attack": 0, "normal": 0,
                                       "associated": 0, "disassociated": 0})
        per_device = defaultdict(lambda: {"events": 0, "attack": 0, "normal": 0,
                                          "associated": 0, "disassociated": 0, "first": None, "last": None})
        totals = Counter()
        timeline = Counter()
        for stamp, mac, association, label in self._rows():
            if device and mac != device:
                continue
            bucket = stamp.replace(second=(stamp.second // window_seconds) * window_seconds, microsecond=0)
            key = (mac, bucket)
            window = windows[key]
            window["events"] += 1
            window[label] += 1
            window[association] += 1
            totals["events"] += 1
            totals[label] += 1
            timeline[bucket.isoformat()] += 1
            stats = per_device[mac]
            stats["events"] += 1
            stats[label] += 1
            stats[association] += 1
            if stats["first"] is None:
                stats["first"] = bucket
            stats["last"] = bucket

        rows = []
        for (mac, bucket), window in sorted(windows.items(), key=lambda item: item[0][1]):
            rows.append({
                "device": mac,
                "window": bucket.isoformat(),
                "events": window["events"],
                "attack": window["attack"],
                "normal": window["normal"],
                "associated": window["associated"],
                "disassociated": window["disassociated"],
                "disassociation_ratio": round(window["disassociated"] / max(1, window["events"]), 3),
                "dominant_label": "attack" if window["attack"] > window["normal"] else "normal",
            })

        device_rows = []
        for mac, stats in per_device.items():
            events = max(1, stats["events"])
            device_rows.append({
                "device": mac,
                "events": stats["events"],
                "attack": stats["attack"],
                "normal": stats["normal"],
                "associated": stats["associated"],
                "disassociated": stats["disassociated"],
                "attack_ratio": round(stats["attack"] / events, 3),
                "disassociation_ratio": round(stats["disassociated"] / events, 3),
                "first_window": stats["first"].isoformat() if stats["first"] else None,
                "last_window": stats["last"].isoformat() if stats["last"] else None,
            })
        device_rows.sort(key=lambda r: (r["attack"], r["events"]), reverse=True)

        temporal = self._temporal(timeline, rows)
        cap = len(rows) if full else MAX_TABLE_ROWS
        analysis = {
            "available": True,
            "summary": self.summary(),
            "window_seconds": int(window_seconds),
            "windows": rows[:cap],
            "window_count": len(rows),
            "devices": device_rows[:cap],
            "device_count": len(device_rows),
            "temporal": temporal["buckets"],
            "temporal_summary": temporal["summary"],
            "totals": dict(totals),
            "limitations": list(LIMITATIONS),
            "truncated": len(rows) > MAX_TABLE_ROWS,
        }
        if device is None and use_cache and not full:
            with self._lock:
                self._analysis = analysis
        return analysis

    def _temporal(self, timeline, window_rows):
        """Corpus volume over time plus the windows with the heaviest disassociation bursts."""
        buckets = [{"window": key, "events": value} for key, value in sorted(timeline.items())]
        peak_events = max((b["events"] for b in buckets), default=0)
        bursts = sorted(window_rows, key=lambda r: (r["disassociated"], r["events"]), reverse=True)[:25]
        attack_windows = [r for r in window_rows if r["attack"] > r["normal"]]
        return {
            "buckets": buckets,
            "summary": {
                "window_count": len(buckets),
                "peak_events_per_window": peak_events,
                "attack_labelled_windows": len(attack_windows),
                "attack_window_ratio": round(len(attack_windows) / max(1, len(window_rows)), 3),
                "largest_disassociation_bursts": [
                    {"device": r["device"], "window": r["window"], "disassociations": r["disassociated"],
                     "events": r["events"]} for r in bursts
                ],
            },
        }

    # -------------------------------------------------------------- detection
    def detection(self, threshold=DEFAULT_DISASSOCIATION_THRESHOLD,
                  ratio=DEFAULT_DISASSOCIATION_RATIO, window_seconds=DEFAULT_WINDOW_SECONDS):
        """Deterministic rule applied to the corpus. No model, no guessing."""
        threshold = int(threshold)
        key = (threshold, float(ratio), int(window_seconds))
        with self._lock:
            if key in self._detections:
                return self._detections[key]
        analysis = self.analyze(window_seconds=window_seconds, use_cache=False, full=True)
        if not analysis.get("available"):
            result = {"available": False, "count": 0, "events": [], "dataset": self.summary(),
                      "rule": _rule_text(threshold, ratio, window_seconds), "limitations": list(LIMITATIONS),
                      "error": analysis.get("error")}
            with self._lock:
                self._detections[key] = result
            return result
        triggered = [
            {
                "device": row["device"], "window": row["window"], "disassociations": row["disassociated"],
                "events": row["events"], "disassociation_ratio": row["disassociation_ratio"],
                "attack_label": row["dominant_label"],
                "rule": _rule_text(threshold, ratio, window_seconds),
            }
            for row in analysis["windows"]
            if row["disassociated"] >= threshold and row["disassociation_ratio"] >= ratio
        ]
        result = {
            "available": True,
            "count": len(triggered),
            "events": triggered[:200],
            "devices_flagged": len({t["device"] for t in triggered}),
            "rule": _rule_text(threshold, ratio, window_seconds),
            "rule_parameters": {"threshold": threshold, "ratio": float(ratio), "window_seconds": int(window_seconds)},
            "dataset": self.summary(),
            "limitations": list(LIMITATIONS),
        }
        with self._lock:
            self._detections[key] = result
        log.info("dataset_detection", extra={"context": {"threshold": threshold, "matches": len(triggered)}})
        return result

    def invalidate(self):
        with self._lock:
            self._summary = None
            self._analysis = None
            self._detections = {}
            self._rows_cache = None
            self._source_signature = None


def _rule_text(threshold, ratio, window_seconds):
    return (f"{window_seconds}-second window with at least {threshold} disassociation events "
            f"and a disassociation ratio of at least {ratio:.0%}")
