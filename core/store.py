"""SQLite persistence for WiFiSentinel.

Everything the application shows comes from here or from live OS telemetry.
Nothing is seeded: an empty database stays empty until the operator creates an
assessment, so a demo can never show fabricated history.

Design notes
------------
* One connection *per thread* (``threading.local``). Sharing a single sqlite3
  connection between the UI thread and background collection workers is unsafe:
  a read issued while a worker is writing can crash the interpreter. Per-thread
  connections plus WAL journaling and a busy timeout make concurrent access safe
  without a global lock on the read path.
* Foreign keys enforced on every connection.
* Schema changes are applied by :func:`migrate`, which is idempotent and versioned
  through ``PRAGMA user_version``. Existing databases are upgraded in place; no data
  is dropped.
"""
from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .logging_setup import get_logger

log = get_logger("store")

SCHEMA_VERSION = 15

SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 7, "Low": 2, "Informational": 0}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def now() -> str:
    """UTC timestamp, second precision, used for every persisted time value."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._local = threading.local()
        self._connections = []
        self.migrate()

    # ------------------------------------------------------------- connections
    @property
    def db(self):
        """Connection bound to the calling thread."""
        return self._conn()

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            self._local.conn = conn
            with self.lock:
                self._connections.append(conn)
        return conn

    # ------------------------------------------------------------------ schema
    def migrate(self):
        conn = self._conn()
        with self.lock, conn:
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            conn.executescript(_BASE_SCHEMA)
            self._add_missing_columns(conn)
            conn.executescript(_INDEXES)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        log.info(
            "store_ready",
            extra={"context": {"path": str(self.path), "schema_from": current, "schema_to": SCHEMA_VERSION}},
        )

    def _add_missing_columns(self, conn):
        """Additive migrations only. Never drops or rewrites an existing column."""
        additive = {
            "assessments": [
                ("notes", "TEXT"),
                ("authorization_note", "TEXT"),
                ("authorized_by", "TEXT"),
                ("authorized_at", "TEXT"),
                ("environment", "TEXT"),
                ("tester", "TEXT"),
                ("last_execution_at", "TEXT"),
            ],
            "findings": [
                ("confidence", "TEXT"),
                ("validation", "TEXT"),
                ("asset", "TEXT"),
                ("category", "TEXT"),
                ("updated_at", "TEXT"),
            ],
            "evidence": [
                ("data_class", "TEXT"),
                ("label", "TEXT"),
                ("test_id", "TEXT"),
            ],
            "executions": [
                ("test_id", "TEXT"),
                ("started_by", "TEXT"),
            ],
            "ai_analyses": [
                ("status", "TEXT"),
            ],
            "networks": [
                ("ssid_observed", "INTEGER"),
                ("ssid_hidden", "INTEGER"),
            ],
        }
        for table, columns in additive.items():
            existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            for column, decl in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        # Historical rows predate data-class labelling; mark them honestly.
        conn.execute("UPDATE evidence SET data_class='live' WHERE data_class IS NULL")

    # ----------------------------------------------------------------- helpers
    def _rows(self, query, args=()):
        return [dict(r) for r in self._conn().execute(query, args).fetchall()]

    def _one(self, query, args=()):
        row = self._conn().execute(query, args).fetchone()
        return dict(row) if row else None

    def close(self):
        with self.lock:
            for conn in self._connections:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._connections = []

    # ------------------------------------------------------ live observations
    def save_observation_snapshot(self, snapshot):
        """Persist an exact, source-labelled OS observation; dedupe identical snapshots."""
        snapshot = dict(snapshot or {})
        kind = str(snapshot.get("kind") or "").strip()
        source = str(snapshot.get("source") or "").strip()
        if kind not in {"wireless", "device"} or not source:
            raise ValueError("Observation kind and source are required.")
        results = snapshot.get("results") if isinstance(snapshot.get("results"), list) else []
        observed_at = str(snapshot.get("observed_at") or now())
        stable = {"kind": kind, "source": source, "method": snapshot.get("method") or "",
                  "interface": snapshot.get("interface") or "", "status": snapshot.get("status") or "success",
                  "data_class": snapshot.get("data_class") or "live",
                  "limitations": snapshot.get("limitations") or []}
        stable_results = [{k:v for k,v in row.items() if k not in {"observed_at", "last_seen"}} if isinstance(row,dict) else row for row in results]
        encoded = json.dumps({**stable,"results":stable_results}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self.lock, self.db:
            row = self.db.execute("SELECT * FROM observation_snapshots WHERE fingerprint=?", (fingerprint,)).fetchone()
            if row:
                self.db.execute("UPDATE observation_snapshots SET last_seen=?,observed_at=?,results_json=? WHERE id=?",
                    (observed_at, observed_at, json.dumps(results,ensure_ascii=False,default=str), row["id"]))
                result = dict(row); result["last_seen"] = observed_at
                result["observed_at"] = observed_at
                result["results_json"] = json.dumps(results,ensure_ascii=False,default=str)
            else:
                sid = uid("OBS")
                self.db.execute("INSERT INTO observation_snapshots(id,kind,source,method,interface,status,started_at,observed_at,first_seen,last_seen,fingerprint,data_class,results_json,limitations_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (sid, kind, source, stable["method"], stable["interface"], stable["status"],
                     snapshot.get("started_at"), observed_at, observed_at, observed_at, fingerprint,
                     stable["data_class"], json.dumps(results, ensure_ascii=False, default=str),
                     json.dumps(stable["limitations"], ensure_ascii=False, default=str)))
                result = self._one("SELECT * FROM observation_snapshots WHERE id=?", (sid,))
        for key, json_key in (("results_json", "results"), ("limitations_json", "limitations")):
            try: result[json_key] = json.loads(result.pop(key) or "[]")
            except (ValueError, TypeError): result[json_key] = []
        return result

    def observation_history(self, kind=None, limit=100):
        if kind and kind not in {"wireless", "device"}:
            raise ValueError("Unknown observation kind.")
        if kind:
            rows = self._rows("SELECT * FROM observation_snapshots WHERE kind=? ORDER BY last_seen DESC,id DESC LIMIT ?", (kind, int(limit)))
        else:
            rows = self._rows("SELECT * FROM observation_snapshots ORDER BY last_seen DESC,id DESC LIMIT ?", (int(limit),))
        for row in rows:
            for key, json_key in (("results_json", "results"), ("limitations_json", "limitations")):
                try: row[json_key] = json.loads(row.pop(key) or "[]")
                except (ValueError, TypeError): row[json_key] = []
        return rows

    def save_wireless_defense_run(self, aid, mode, status, scope, targets, result, evidence):
        if mode not in {"passive", "simulation"}: raise ValueError("Only passive analysis and lab simulation are supported.")
        run_id, evidence_id, stamp = uid("WDR"), uid("EVD"), now()
        result = dict(result or {}); evidence = dict(evidence or {})
        evidence_content=json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",",":"), default=str)
        evidence_digest=hashlib.sha256(evidence_content.encode("utf-8")).hexdigest()
        with self.lock, self.db:
            self.db.execute("INSERT INTO evidence(id,assessment_id,execution_id,type,source,content,metadata,created_at,data_class,label,test_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (evidence_id, aid, None, "wireless_defense_assessment", "capture_analysis" if mode == "passive" else "lab_simulator",
                 evidence_content, json.dumps({"mode":mode,"scope":scope,"content_sha256":evidence_digest}), stamp,
                 "capture" if mode == "passive" else "simulation", "Passive wireless defense assessment" if mode == "passive" else "SIMULATED LAB", "deauth_assessment"))
            self.db.execute("INSERT INTO wireless_defense_runs(id,assessment_id,mode,status,scope,ap_evidence_ref,targets_json,authorization_evidence_ref,started_at,completed_at,result_json,evidence_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, aid, mode, status, scope, evidence.get("ap_evidence_ref"), json.dumps(targets),
                 evidence_id, stamp, stamp, json.dumps(result, ensure_ascii=False, sort_keys=True), evidence_id))
        return self.wireless_defense_run(run_id)

    # ------------------------------------------------------------- Wi-Fi audits
    def save_wifi_audit(self, payload):
        """Persist an immutable audit payload and a digest for integrity checks."""
        if not isinstance(payload, dict) or not payload.get("model_version"):
            raise ValueError("A Wi-Fi audit payload with a model version is required.")
        audit_id = uid("WFA")
        stamp = str(payload.get("created_at") or now())
        payload = dict(payload)
        payload.setdefault("created_at", stamp)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        score = payload.get("score") if isinstance(payload.get("score"), dict) else {}
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO wifi_audits(id,created_at,model_version,score_status,score_value,score_band,"
                "payload_json,payload_sha256) VALUES (?,?,?,?,?,?,?,?)",
                (audit_id, stamp, str(payload["model_version"]), str(score.get("status") or "unknown"),
                 score.get("value"), score.get("band"), encoded, digest),
            )
        return self.wifi_audit(audit_id)

    def wifi_audit(self, audit_id):
        row = self._one("SELECT * FROM wifi_audits WHERE id=?", (audit_id,))
        if not row:
            return None
        decoded = _decode_wifi_audit(row)
        decoded["remediations"] = self.wifi_audit_remediations(audit_id)
        return decoded

    def wifi_audits(self, limit=50):
        limit = max(1, min(int(limit), 500))
        rows = [_decode_wifi_audit(row) for row in self._rows(
            "SELECT * FROM wifi_audits ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))]
        for row in rows:
            row["remediations"] = self.wifi_audit_remediations(row["id"])
        return rows

    def set_wifi_audit_remediation(self, audit_id, finding_id, applied):
        audit = self.wifi_audit(audit_id)
        if not audit:
            raise ValueError("Wi-Fi audit was not found.")
        if not audit.get("integrity_valid"):
            raise ValueError("Wi-Fi audit integrity check failed.")
        valid_ids = {str(item.get("id")) for item in (audit.get("payload") or {}).get("findings", [])}
        if finding_id not in valid_ids:
            raise ValueError("Finding does not belong to this Wi-Fi audit.")
        status = "applied" if applied is True else "open"
        stamp = now()
        with self.lock, self.db:
            self.db.execute("INSERT INTO wifi_audit_remediations(audit_id,finding_id,status,updated_at) VALUES (?,?,?,?) "
                            "ON CONFLICT(audit_id,finding_id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at",
                            (audit_id, finding_id, status, stamp))
        return next(row for row in self.wifi_audit_remediations(audit_id) if row["finding_id"] == finding_id)

    def wifi_audit_remediations(self, audit_id):
        return self._rows("SELECT audit_id,finding_id,status,updated_at FROM wifi_audit_remediations WHERE audit_id=? ORDER BY finding_id",
                          (audit_id,))

    def wireless_defense_run(self, run_id):
        row = self._one("SELECT * FROM wireless_defense_runs WHERE id=?", (run_id,))
        if row:
            for key in ("targets_json", "result_json"):
                try: row[key[:-5] if key.endswith('_json') else key] = json.loads(row.pop(key) or ("[]" if key == "targets_json" else "{}"))
                except (ValueError, TypeError): row[key[:-5]] = [] if key == "targets_json" else {}
        return row

    def wireless_defense_runs(self, aid, limit=100):
        rows=self._rows("SELECT * FROM wireless_defense_runs WHERE assessment_id=? ORDER BY started_at DESC,id DESC LIMIT ?",(aid,int(limit)))
        for row in rows:
            try: row["targets"]=json.loads(row.pop("targets_json") or "[]")
            except (ValueError,TypeError): row["targets"]=[]
            try: row["result"]=json.loads(row.pop("result_json") or "{}")
            except (ValueError,TypeError): row["result"]={}
        return rows

    # ------------------------------------------------------------- assessments
    def create_assessment(self, data):
        data = data or {}
        scope_policy = data.get("scope_policy")
        if scope_policy is not None:
            scope_policy = self._normalize_scope_policy(scope_policy)
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("Assessment name is required.")
        aid = uid("ASM")
        stamp = now()
        authorization = 1 if data.get("authorization") else 0
        values = (
            aid,
            name,
            data.get("description") or "",
            data.get("target") or "",
            data.get("environment") or "",
            data.get("tester") or "",
            authorization,
            data.get("wireless_scope") or "",
            data.get("network_scope") or "",
            data.get("interface") or "",
            "ready",
            stamp,
            stamp,
            None,
            None,
            data.get("notes") or "",
            data.get("authorization_note") or "",
            data.get("authorized_by") or "",
            stamp if authorization else None,
        )
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO assessments (id,name,description,target,environment,tester,authorization,wireless_scope,"
                "network_scope,interface,status,created_at,updated_at,started_at,completed_at,notes,authorization_note,"
                "authorized_by,authorized_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            )
            self.db.execute(
                "INSERT INTO events (assessment_id,execution_id,event_type,message,created_at) VALUES (?,?,?,?,?)",
                (aid, None, "lifecycle", "Assessment created", stamp),
            )
            if scope_policy is not None:
                self.db.execute(
                    "INSERT INTO engagement_scopes(assessment_id,policy_json,updated_at) VALUES (?,?,?)",
                    (aid, json.dumps(scope_policy, ensure_ascii=False, sort_keys=True), stamp),
                )
                self.db.execute(
                    "INSERT INTO scope_change_history(id,assessment_id,changed_by,policy_json,created_at) VALUES (?,?,?,?,?)",
                    (uid("SCP"), aid, str(data.get("authorized_by") or "local_operator"),
                     json.dumps(scope_policy, ensure_ascii=False, sort_keys=True), stamp),
                )
        log.info("assessment_created", extra={"context": {"assessment_id": aid, "authorized": bool(authorization)}})
        return self.assessment(aid)

    def assessments(self):
        return self._rows("SELECT * FROM assessments ORDER BY created_at DESC, id DESC")

    def assessment_registry(self):
        return self._rows(
            "SELECT a.*, COUNT(f.id) AS findings_count, "
            "SUM(CASE WHEN f.severity='Critical' THEN 1 ELSE 0 END) AS critical_count, "
            "SUM(CASE WHEN f.severity='High' THEN 1 ELSE 0 END) AS high_count, "
            "SUM(CASE WHEN f.severity='Medium' THEN 1 ELSE 0 END) AS medium_count "
            "FROM assessments a LEFT JOIN findings f ON f.assessment_id=a.id "
            "GROUP BY a.id ORDER BY a.created_at DESC, a.id DESC"
        )

    def assessment(self, aid):
        return self._one("SELECT * FROM assessments WHERE id=?", (aid,))

    @staticmethod
    def _normalize_scope_policy(policy):
        if not isinstance(policy, dict):
            raise ValueError("Engagement scope must be an object.")
        fields = {
            "active", "authorized_sites", "locations", "approved_ssids", "approved_bssids",
            "ip_ranges", "network_segments", "testing_start", "testing_end", "testing_windows",
            "permitted_activities", "excluded_hosts", "excluded_ip_ranges", "excluded_devices",
            "emergency_contacts", "rules_of_engagement", "approver",
        }
        result = {key: policy[key] for key in fields if key in policy}
        list_fields = fields - {"active", "testing_start", "testing_end", "rules_of_engagement", "approver"}
        for key in list_fields:
            value = result.get(key, [])
            if not isinstance(value, list):
                raise ValueError(f"{key} must be a list.")
            result[key] = [str(item).strip()[:500] for item in value if str(item).strip()]
        if "active" in result and not isinstance(result["active"], bool):
            raise ValueError("Scope active must be a boolean.")
        for key in ("testing_start", "testing_end", "rules_of_engagement", "approver"):
            if key in result:
                result[key] = str(result[key] or "").strip()[:4000]
        return result

    def scope_policy(self, aid):
        row = self._one("SELECT policy_json,updated_at FROM engagement_scopes WHERE assessment_id=?", (aid,))
        if not row:
            return {"active": False, "permitted_activities": [], "excluded_hosts": [],
                    "excluded_ip_ranges": [], "testing_windows": [], "updated_at": None}
        try:
            policy = json.loads(row["policy_json"] or "{}")
        except (ValueError, TypeError):
            policy = {}
        return {**policy, "updated_at": row["updated_at"]}

    def set_scope_policy(self, aid, policy, changed_by="local_operator"):
        if not self.assessment(aid):
            raise ValueError("Assessment not found.")
        normalized = self._normalize_scope_policy(policy)
        stamp = now()
        encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO engagement_scopes(assessment_id,policy_json,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(assessment_id) DO UPDATE SET policy_json=excluded.policy_json,updated_at=excluded.updated_at",
                (aid, encoded, stamp),
            )
            self.db.execute(
                "INSERT INTO scope_change_history(id,assessment_id,changed_by,policy_json,created_at) VALUES (?,?,?,?,?)",
                (uid("SCP"), aid, str(changed_by or "local_operator")[:120], encoded, stamp),
            )
            self.db.execute(
                "INSERT INTO events(assessment_id,execution_id,event_type,message,created_at) VALUES (?,?,?,?,?)",
                (aid, None, "scope_changed", "Engagement scope manifest updated", stamp),
            )
        return self.scope_policy(aid)

    def scope_history(self, aid, limit=100):
        rows = self._rows(
            "SELECT id,assessment_id,changed_by,policy_json,created_at FROM scope_change_history "
            "WHERE assessment_id=? ORDER BY rowid DESC LIMIT ?", (aid, max(1, min(int(limit), 500)))
        )
        for row in rows:
            try:
                row["policy"] = json.loads(row.pop("policy_json") or "{}")
            except (ValueError, TypeError):
                row["policy"] = {}
        return rows

    def add_authorization_document(self, aid, document, uploaded_by="local_operator"):
        document = dict(document or {})
        if not self.assessment(aid):
            raise ValueError("Assessment not found.")
        digest = str(document.get("sha256") or "").lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("Authorization document SHA-256 is invalid.")
        stored_path = str(document.get("stored_path") or "")
        relative = Path(stored_path)
        if not stored_path or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Authorization document storage path is invalid.")
        doc_id, stamp = uid("DOC"), now()
        with self.lock, self.db:
            self.db.execute("INSERT INTO authorization_documents(id,assessment_id,filename,stored_path,sha256,size_bytes,document_format,uploaded_at,uploaded_by,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                (doc_id, aid, str(document.get("filename") or "authorization document")[:255], stored_path,
                 digest, int(document.get("size_bytes") or 0), str(document.get("document_format") or "UNKNOWN"),
                 stamp, str(uploaded_by or "local_operator")[:120]))
            self.db.execute("INSERT INTO authorization_document_history(id,assessment_id,document_id,action,sha256,changed_by,created_at) VALUES (?,?,?,?,?,?,?)",
                (uid("DCH"), aid, doc_id, "attached", digest, str(uploaded_by or "local_operator")[:120], stamp))
        return self.authorization_document(aid, doc_id)

    def authorization_document(self, aid, document_id):
        return self._one("SELECT id,assessment_id,filename,stored_path,sha256,size_bytes,document_format,uploaded_at,uploaded_by,deleted_at FROM authorization_documents WHERE assessment_id=? AND id=?",
                         (aid, document_id))

    def authorization_documents(self, aid, include_deleted=False):
        query = "SELECT id,assessment_id,filename,stored_path,sha256,size_bytes,document_format,uploaded_at,uploaded_by,deleted_at FROM authorization_documents WHERE assessment_id=?"
        if not include_deleted:
            query += " AND deleted_at IS NULL"
        query += " ORDER BY uploaded_at DESC,id DESC"
        return self._rows(query, (aid,))

    def remove_authorization_document(self, aid, document_id, changed_by="local_operator"):
        stamp = now()
        with self.lock, self.db:
            row = self.db.execute("SELECT sha256,deleted_at FROM authorization_documents WHERE assessment_id=? AND id=?",
                                  (aid, document_id)).fetchone()
            if not row:
                raise ValueError("Authorization document not found.")
            if row["deleted_at"]:
                return False
            self.db.execute("UPDATE authorization_documents SET deleted_at=? WHERE assessment_id=? AND id=?",
                            (stamp, aid, document_id))
            self.db.execute("INSERT INTO authorization_document_history(id,assessment_id,document_id,action,sha256,changed_by,created_at) VALUES (?,?,?,?,?,?,?)",
                            (uid("DCH"), aid, document_id, "removed", row["sha256"], str(changed_by or "local_operator")[:120], stamp))
        return True

    def authorization_document_history(self, aid, limit=200):
        return self._rows("SELECT id,assessment_id,document_id,action,sha256,changed_by,created_at FROM authorization_document_history WHERE assessment_id=? ORDER BY rowid DESC LIMIT ?",
                          (aid, max(1, min(int(limit), 1000))))

    def create_training_session(self, session_id, token_sha256, host, port, created_at, expires_at):
        digest = str(token_sha256 or "").lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("Training session token digest is invalid.")
        if host != "127.0.0.1":
            raise ValueError("Training simulator sessions must bind to loopback only.")
        stamp = str(created_at or now())
        with self.lock, self.db:
            self.db.execute("INSERT INTO training_sessions(id,token_sha256,host,port,status,created_at,expires_at,ended_at) VALUES (?,?,?,?,?,?,?,NULL)",
                            (str(session_id), digest, host, int(port), "active", stamp, str(expires_at)))
        return self.training_session(session_id)

    def training_session(self, session_id):
        row = self._one("SELECT id,token_sha256,host,port,status,created_at,expires_at,ended_at FROM training_sessions WHERE id=?", (str(session_id),))
        if not row:
            return None
        row["events"] = self._training_event_counts(session_id)
        return row

    def add_training_event(self, session_id, event, choice=None, observed_at=None):
        allowed = {"visit", "click", "synthetic_response"}
        if event not in allowed or (event == "synthetic_response" and choice not in {"yes", "no"}) or (event != "synthetic_response" and choice is not None):
            raise ValueError("Training simulator event is not an allowed synthetic event.")
        stamp = str(observed_at or now())
        with self.lock, self.db:
            row = self.db.execute("SELECT status,expires_at FROM training_sessions WHERE id=?", (str(session_id),)).fetchone()
            if not row or row["status"] != "active":
                raise ValueError("Training session is not active.")
            self.db.execute("INSERT INTO training_events(session_id,event,choice,created_at) VALUES (?,?,?,?)",
                            (str(session_id), event, choice, stamp))
        return True

    def finish_training_session(self, session_id, status, ended_at=None):
        if status not in {"stopped", "expired"}:
            raise ValueError("Training session status is invalid.")
        with self.lock, self.db:
            self.db.execute("UPDATE training_sessions SET status=?,ended_at=COALESCE(ended_at,?) WHERE id=? AND status='active'",
                            (status, str(ended_at or now()), str(session_id)))
        return self.training_session(session_id)

    def recover_interrupted_training_sessions(self, ended_at=None):
        """Mark persisted listeners inactive after process restart; never delete their event history."""
        stamp = str(ended_at or now())
        with self.lock, self.db:
            cursor = self.db.execute("UPDATE training_sessions SET status='stopped',ended_at=COALESCE(ended_at,?) WHERE status='active'",
                                     (stamp,))
            return cursor.rowcount

    def _training_event_counts(self, session_id):
        row = self._one("SELECT SUM(CASE WHEN event='visit' THEN 1 ELSE 0 END) AS visits,"
                        "SUM(CASE WHEN event='click' THEN 1 ELSE 0 END) AS clicks,"
                        "SUM(CASE WHEN event='synthetic_response' AND choice='yes' THEN 1 ELSE 0 END) AS yes_count,"
                        "SUM(CASE WHEN event='synthetic_response' AND choice='no' THEN 1 ELSE 0 END) AS no_count "
                        "FROM training_events WHERE session_id=?", (str(session_id),)) or {}
        return {"visit": row.get("visits") or 0, "click": row.get("clicks") or 0,
                "synthetic_yes": row.get("yes_count") or 0, "synthetic_no": row.get("no_count") or 0}

    def training_sessions(self, limit=100):
        rows = self._rows("SELECT id,token_sha256,host,port,status,created_at,expires_at,ended_at FROM training_sessions ORDER BY rowid DESC LIMIT ?",
                          (max(1, min(int(limit), 500)),))
        for row in rows:
            row["events"] = self._training_event_counts(row["id"])
        return rows

    def purge_training_sessions_before(self, cutoff):
        try:
            parsed = datetime.fromisoformat(str(cutoff).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Training history cutoff must be an ISO timestamp.") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Training history cutoff must include a timezone.")
        stamp = parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        with self.lock, self.db:
            cursor = self.db.execute("DELETE FROM training_sessions WHERE status!='active' AND created_at<?", (stamp,))
            return cursor.rowcount

    def update_assessment(self, aid, **fields):
        allowed = {
            "name", "description", "target", "environment", "tester", "wireless_scope",
            "network_scope", "interface", "notes", "authorization_note", "authorized_by",
            "authorization", "authorized_at", "status", "started_at", "completed_at", "last_execution_at",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if "name" in updates:
            updates["name"] = str(updates["name"] or "").strip()
            if not updates["name"]:
                raise ValueError("Assessment name is required.")
        if not updates:
            return self.assessment(aid)
        assignments = ", ".join(f"{k}=?" for k in updates)
        with self.lock, self.db:
            self.db.execute(
                f"UPDATE assessments SET {assignments}, updated_at=? WHERE id=?",
                tuple(updates.values()) + (now(), aid),
            )
        return self.assessment(aid)

    def set_authorization(self, aid, authorized, note="", authorized_by=""):
        return self.update_assessment(
            aid,
            authorization=1 if authorized else 0,
            authorization_note=note or "",
            authorized_by=authorized_by or "",
            authorized_at=now() if authorized else None,
        )

    def set_status(self, aid, status, **extra):
        allowed_extra = {
            "started_at", "completed_at", "last_execution_at",
        }
        updates = {"status": status}
        updates.update({k: v for k, v in extra.items() if k in allowed_extra})
        return self.update_assessment(aid, **updates)

    def delete_assessment(self, aid):
        with self.lock, self.db:
            for table in ("events", "evidence", "findings", "networks", "devices", "executions", "ai_analyses"):
                self.db.execute(f"DELETE FROM {table} WHERE assessment_id=?", (aid,))
            cursor = self.db.execute("DELETE FROM assessments WHERE id=?", (aid,))
        log.info("assessment_deleted", extra={"context": {"assessment_id": aid, "rows": cursor.rowcount}})
        return cursor.rowcount > 0

    # -------------------------------------------------------------- executions
    def start_execution(self, aid, test_type, test_id=None, started_by=""):
        ex = uid("EXE")
        stamp = now()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO executions (id,assessment_id,test_type,test_id,status,stage,progress,started_at,"
                "completed_at,error,started_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ex, aid, test_type, test_id, "running", "preflight", 0, stamp, None, None, started_by),
            )
            self.db.execute(
                "UPDATE assessments SET status=?, started_at=COALESCE(started_at,?), updated_at=?, "
                "last_execution_at=? WHERE id=?",
                ("running", stamp, stamp, stamp, aid),
            )
        self.event(aid, ex, "execution", f"Execution started: {test_type}")
        log.info("execution_started", extra={"context": {"assessment_id": aid, "execution_id": ex, "test": test_type}})
        return ex

    def update_execution(self, exid, stage=None, progress=None, status=None, error=None):
        sets = []
        args = []
        if stage is not None:
            sets.append("stage=?")
            args.append(stage)
        if progress is not None:
            sets.append("progress=?")
            args.append(int(progress))
        if status is not None:
            sets.append("status=?")
            args.append(status)
        if error is not None:
            sets.append("error=?")
            args.append(error)
        if status in ("completed", "failed", "blocked", "cancelled"):
            sets.append("completed_at=?")
            args.append(now())
        if not sets:
            return self.execution(exid)
        args.append(exid)
        with self.lock, self.db:
            self.db.execute(f"UPDATE executions SET {', '.join(sets)} WHERE id=?", tuple(args))
        return self.execution(exid)

    def execution(self, exid):
        return self._one("SELECT * FROM executions WHERE id=?", (exid,))

    def executions(self, aid, limit=25):
        return self._rows(
            "SELECT * FROM executions WHERE assessment_id=? ORDER BY started_at DESC, rowid DESC LIMIT ?",
            (aid, int(limit)),
        )

    def latest_execution(self, aid):
        return self._one(
            "SELECT * FROM executions WHERE assessment_id=? ORDER BY started_at DESC, rowid DESC LIMIT 1", (aid,)
        )

    def execution_completed_at(self, exid):
        row = self._one("SELECT completed_at FROM executions WHERE id=?", (exid,))
        return (row or {}).get("completed_at") or now()

    def active_execution(self, aid):
        return self._one(
            "SELECT * FROM executions WHERE assessment_id=? AND status='running' ORDER BY started_at DESC LIMIT 1",
            (aid,),
        )

    # ------------------------------------------------------------------ events
    def event(self, aid, exid, event_type, message):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO events (assessment_id,execution_id,event_type,message,created_at) VALUES (?,?,?,?,?)",
                (aid, exid, event_type, message, now()),
            )

    def events(self, aid, limit=200):
        return self._rows(
            "SELECT * FROM events WHERE assessment_id=? ORDER BY id DESC LIMIT ?", (aid, int(limit))
        )

    # ---------------------------------------------------------------- observed
    def add_network(self, aid, n):
        nid = uid("NET")
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO networks (id,assessment_id,ssid,bssid,channel,frequency,signal_pct,signal_dbm,auth,"
                "cipher,radio_type,observed_at,data_class,ssid_observed,ssid_hidden) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    nid, aid, n.get("ssid"), n.get("bssid"), n.get("channel"), n.get("frequency_ghz"),
                    n.get("signal_pct"), n.get("signal_dbm"), n.get("auth"), n.get("cipher"),
                    n.get("radio_type"), n.get("observed_at") or now(), "live",
                    int(bool(n.get("ssid_observed"))), int(bool(n.get("ssid_hidden"))),
                ),
            )
        return nid

    def add_device(self, aid, d):
        did = uid("DEV")
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO devices (id,assessment_id,ip,mac,hostname,vendor,os,status,is_gateway,is_self,"
                "open_ports,device_type,interface,observed_at,data_class) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    did, aid, d.get("ip"), d.get("mac"), d.get("hostname"), d.get("vendor"), d.get("os"),
                    d.get("status"), int(bool(d.get("is_gateway"))), int(bool(d.get("is_self"))),
                    json.dumps(d.get("open_ports") or []), d.get("type") or d.get("device_type"),
                    d.get("interface"), now(), "live",
                ),
            )
        return did

    def save_device_discovery(self, job):
        """Upsert one explicitly authorized local scan and its observed responders."""
        if not isinstance(job, dict) or not job.get("id"):
            raise ValueError("A device-discovery job ID is required.")
        stamp = now()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO device_discovery_runs (id,scope,interface,status,started_at,finished_at,checked,total,"
                "results,limitations,error,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status,finished_at=excluded.finished_at,"
                "checked=excluded.checked,total=excluded.total,results=excluded.results,limitations=excluded.limitations,"
                "error=excluded.error,updated_at=excluded.updated_at",
                (job["id"], job.get("scope") or "", job.get("interface"), job.get("status") or "unknown",
                 job.get("started_at"), job.get("finished_at"), int(job.get("checked") or 0),
                 int(job.get("total") or 0), json.dumps(job.get("results") or [], default=str),
                 json.dumps(job.get("limitations") or [], default=str), job.get("error"), stamp),
            )
        return self.device_discovery(job["id"])

    def device_discovery(self, job_id):
        row = self._one("SELECT * FROM device_discovery_runs WHERE id=?", (job_id,))
        return _decode_device_discovery(row) if row else None

    def latest_device_discovery(self, limit=10):
        return [_decode_device_discovery(row) for row in self._rows(
            "SELECT * FROM device_discovery_runs ORDER BY started_at DESC,id DESC LIMIT ?", (int(limit),)
        )]

    def recover_interrupted_device_discoveries(self):
        """Mark unfinished scans from a previous app process without implying success."""
        with self.lock, self.db:
            cursor = self.db.execute(
                "UPDATE device_discovery_runs SET status='interrupted',"
                "finished_at=COALESCE(finished_at,?),error=COALESCE(error,'Application closed before scan completion.'),updated_at=? "
                "WHERE status='running'", (now(), now())
            )
        return cursor.rowcount

    def networks(self, aid):
        return self._rows(
            "SELECT * FROM networks WHERE assessment_id=? ORDER BY (signal_pct IS NULL), signal_pct DESC, ssid",
            (aid,),
        )

    def devices(self, aid):
        rows = self._rows(
            "SELECT * FROM devices WHERE assessment_id=? ORDER BY is_self DESC, is_gateway DESC, ip", (aid,)
        )
        for row in rows:
            try:
                row["open_ports"] = json.loads(row["open_ports"] or "[]")
            except (ValueError, TypeError):
                row["open_ports"] = []
        return rows

    def device_observations(self, limit=500):
        """Read recent persisted neighbor-cache observations without merging identities."""
        bounded = max(1, min(int(limit), 2000))
        rows = self._rows("SELECT * FROM devices ORDER BY observed_at DESC,id DESC LIMIT ?", (bounded,))
        for row in rows:
            try: row["open_ports"] = json.loads(row.get("open_ports") or "[]")
            except (ValueError, TypeError): row["open_ports"] = []
        return rows

    def nmap_observation_evidence(self, limit=500):
        """Read recent Nmap evidence payloads for device/service observation views."""
        bounded = max(1, min(int(limit), 2000))
        rows = self._rows("SELECT id,assessment_id,content,metadata,created_at,data_class FROM evidence "
                          "WHERE type='nmap_scan' ORDER BY created_at DESC,rowid DESC LIMIT ?", (bounded,))
        for row in rows:
            try: row["payload"] = json.loads(row.pop("content") or "{}")
            except (ValueError, TypeError): row["payload"] = {}
            try: row["metadata"] = json.loads(row.get("metadata") or "{}")
            except (ValueError, TypeError): row["metadata"] = {}
        return rows

    # ---------------------------------------------------------------- evidence
    def add_evidence(self, aid, exid, type_, source, content, meta=None, data_class="live", label=None, test_id=None):
        eid = uid("EVD")
        meta = meta or {}
        test_id = test_id or meta.get("test")
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO evidence (id,assessment_id,execution_id,type,source,content,metadata,created_at,"
                "data_class,label,test_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    eid, aid, exid, type_, source,
                    content if isinstance(content, str) else json.dumps(content, indent=2, default=str),
                    json.dumps(meta, default=str), now(), data_class, label, test_id,
                ),
            )
        return eid

    def save_capture_analysis(self, aid, result, stored_path):
        """Persist a validated offline capture, its evidence and any finding atomically."""
        if not isinstance(result, dict):
            raise ValueError("Capture analysis result is required.")
        digest = str(result.get("sha256") or "").lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("A valid capture SHA-256 is required.")
        if not self.assessment(aid):
            raise ValueError("Assessment not found.")
        stamp = now()
        with self.lock, self.db:
            existing = self.db.execute(
                "SELECT * FROM capture_imports WHERE assessment_id=? AND source_sha256=?", (aid, digest)
            ).fetchone()
            if existing:
                row = dict(existing)
                row["analysis"] = json.loads(row["analysis"] or "{}")
                return {"duplicate": True, "capture": row, "evidence_id": row["evidence_id"],
                        "execution_id": row["execution_id"]}

            capture_id, execution_id, evidence_id = uid("CAP"), uid("EXE"), uid("EVD")
            finding_id = uid("FND") if int(result.get("candidate_exchanges") or 0) > 0 else None
            meta = {
                "data_class": "capture", "sha256": digest,
                "filename": str(result.get("filename") or "capture"),
                "capture_format": str(result.get("capture_format") or "unknown"),
                "size_bytes": int(result.get("size_bytes") or 0),
                "parser_version": str(result.get("parser_version") or "unknown"),
                "imported_at": stamp, "test": "offline_capture",
            }
            self.db.execute(
                "INSERT INTO executions (id,assessment_id,test_type,test_id,status,stage,progress,started_at,completed_at,error,started_by) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (execution_id, aid, "Offline capture analysis", "offline_capture", "completed", "completed", 100,
                 stamp, stamp, None, "local_operator"),
            )
            self.db.execute(
                "INSERT INTO evidence (id,assessment_id,execution_id,type,source,content,metadata,created_at,data_class,label,test_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (evidence_id, aid, execution_id, "capture_analysis", "User-supplied local PCAP/PCAPNG",
                 json.dumps(result, ensure_ascii=False, default=str), json.dumps(meta), stamp, "capture",
                 "Offline capture analysis", "offline_capture"),
            )
            self.db.execute(
                "INSERT INTO capture_imports (id,assessment_id,execution_id,evidence_id,source_sha256,filename,stored_path,"
                "capture_format,size_bytes,parser_version,imported_at,analysis_status,analysis) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (capture_id, aid, execution_id, evidence_id, digest, meta["filename"], stored_path,
                 meta["capture_format"], meta["size_bytes"], meta["parser_version"], stamp, "completed",
                 json.dumps(result, ensure_ascii=False, default=str)),
            )
            if finding_id:
                self.db.execute(
                    "INSERT INTO findings (id,assessment_id,execution_id,title,severity,description,impact,source_test,"
                    "detection_logic,recommendation,status,evidence_id,created_at,confidence,validation,asset,category,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (finding_id, aid, execution_id, "Candidate WPA four-way exchange observed", "Informational",
                     "The offline capture contains an EAPOL message and replay-counter pattern consistent with a candidate four-way exchange.",
                     "This is a packet-pattern observation only; it does not establish a usable key exchange, password, or vulnerability.",
                     "capture_analysis", "Pattern detection uses observed pairwise EAPOL key message flags and replay counters.",
                     "Validate capture provenance and completeness, then review the authorized AP configuration and client telemetry.",
                     "open", evidence_id, stamp, "Low",
                     "Pattern observation only; capture completeness and exchange usability were not independently verified.",
                     "In-scope wireless asset", "Offline capture analysis", stamp),
                )
            self.db.execute(
                "INSERT INTO events (assessment_id,execution_id,event_type,message,created_at) VALUES (?,?,?,?,?)",
                (aid, execution_id, "capture_analysis", "Offline capture analysis completed; no radio activity occurred.", stamp),
            )
            self.db.execute(
                "UPDATE assessments SET status='completed',started_at=COALESCE(started_at,?),completed_at=?,"
                "updated_at=?,last_execution_at=? WHERE id=?", (stamp, stamp, stamp, stamp, aid),
            )
            row = dict(self.db.execute("SELECT * FROM capture_imports WHERE id=?", (capture_id,)).fetchone())
            row["analysis"] = json.loads(row["analysis"] or "{}")
        return {"duplicate": False, "capture": row, "evidence_id": evidence_id, "execution_id": execution_id}

    def capture_imports(self, aid, include_analysis=False):
        if include_analysis:
            rows = self._rows("SELECT * FROM capture_imports WHERE assessment_id=? ORDER BY imported_at DESC,id DESC", (aid,))
            for row in rows:
                try:
                    row["analysis"] = json.loads(row.get("analysis") or "{}")
                except (ValueError, TypeError):
                    row["analysis"] = {}
        else:
            rows = self._rows(
                "SELECT id,assessment_id,execution_id,evidence_id,source_sha256,filename,stored_path,capture_format,"
                "size_bytes,parser_version,imported_at,analysis_status FROM capture_imports "
                "WHERE assessment_id=? ORDER BY imported_at DESC,id DESC", (aid,)
            )
        return rows

    def all_capture_imports(self, limit=200):
        return self._rows("SELECT id,assessment_id,execution_id,evidence_id,source_sha256,filename,capture_format,size_bytes,parser_version,imported_at,analysis_status FROM capture_imports ORDER BY imported_at DESC,id DESC LIMIT ?", (int(limit),))

    def capture_import(self, capture_id):
        row = self._one("SELECT * FROM capture_imports WHERE id=?", (capture_id,))
        if row:
            try: row["analysis"] = json.loads(row.get("analysis") or "{}")
            except (ValueError, TypeError): row["analysis"] = {}
        return row

    def evidence_count(self, aid, test_id):
        row = self._one("SELECT COUNT(*) AS n FROM evidence WHERE assessment_id=? AND test_id=?", (aid, test_id))
        return (row or {}).get("n", 0)

    def evidence(self, aid, limit=200):
        rows = self._rows(
            "SELECT id,assessment_id,execution_id,type,source,metadata,created_at,data_class,label,test_id,"
            "length(content) AS content_length, substr(content,1,2000) AS content_preview "
            "FROM evidence WHERE assessment_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (aid, int(limit)),
        )
        for row in rows:
            try:
                row["metadata"] = json.loads(row["metadata"] or "{}")
            except (ValueError, TypeError):
                row["metadata"] = {}
        return rows

    def evidence_item(self, aid, eid):
        """Full evidence body. Fetched on demand so list views stay cheap."""
        row = self._one("SELECT * FROM evidence WHERE id=? AND assessment_id=?", (eid, aid))
        if row:
            try:
                row["metadata"] = json.loads(row["metadata"] or "{}")
            except (ValueError, TypeError):
                row["metadata"] = {}
        return row

    # ---------------------------------------------------------------- findings
    def add_finding(self, aid, exid, title, severity, description, impact, source, logic, recommendation,
                    evidence_id=None, confidence="Medium", validation="", asset="", category="", status="open"):
        fid = uid("FND")
        severity = severity if severity in SEVERITY_WEIGHTS else "Informational"
        stamp = now()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO findings (id,assessment_id,execution_id,title,severity,description,impact,source_test,"
                "detection_logic,recommendation,status,evidence_id,created_at,confidence,validation,asset,category,"
                "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    fid, aid, exid, title, severity, description, impact, source, logic, recommendation,
                    status, evidence_id, stamp, confidence, validation, asset, category, stamp,
                ),
            )
        log.info(
            "finding_recorded",
            extra={"context": {"assessment_id": aid, "finding_id": fid, "severity": severity, "source": source}},
        )
        return fid

    def finding(self, aid, fid):
        return self._one("SELECT * FROM findings WHERE id=? AND assessment_id=?", (fid, aid))

    def set_finding_status(self, aid, fid, status):
        with self.lock, self.db:
            self.db.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE id=? AND assessment_id=?",
                (status, now(), fid, aid),
            )
        return self.finding(aid, fid)

    def findings_for_execution(self, aid, execution_id):
        return self._rows("SELECT * FROM findings WHERE assessment_id=? AND execution_id=? ORDER BY created_at,id",
                          (aid, execution_id))

    def record_finding_retest(self, aid, finding_id, status, execution_id=None, evidence_id=None, detail=""):
        if status not in {"fixed", "partial", "unresolved", "unable_to_verify"}:
            raise ValueError("Unsupported finding retest status.")
        retest_id, stamp = uid("RTS"), now()
        with self.lock, self.db:
            if not self.db.execute("SELECT 1 FROM findings WHERE id=? AND assessment_id=?",
                                   (finding_id, aid)).fetchone():
                raise ValueError("Finding was not found in this assessment.")
            if evidence_id and not self.db.execute("SELECT 1 FROM evidence WHERE id=? AND assessment_id=?",
                                                   (evidence_id, aid)).fetchone():
                raise ValueError("Retest evidence must belong to the same assessment.")
            if execution_id and not self.db.execute("SELECT 1 FROM executions WHERE id=? AND assessment_id=?",
                                                    (execution_id, aid)).fetchone():
                raise ValueError("Retest execution must belong to the same assessment.")
            self.db.execute("INSERT INTO finding_retests(id,assessment_id,finding_id,status,execution_id,evidence_id,detail,created_at) "
                            "VALUES (?,?,?,?,?,?,?,?)",
                            (retest_id, aid, finding_id, status, execution_id, evidence_id,
                             str(detail)[:2000], stamp))
        return self.finding_retest(aid, retest_id)

    def finding_retest(self, aid, retest_id):
        return self._one("SELECT * FROM finding_retests WHERE assessment_id=? AND id=?", (aid, retest_id))

    def finding_retests(self, aid, finding_id=None, limit=500):
        bounded = max(1, min(int(limit), 2000))
        if finding_id:
            return self._rows("SELECT * FROM finding_retests WHERE assessment_id=? AND finding_id=? "
                               "ORDER BY created_at DESC,id DESC LIMIT ?", (aid, finding_id, bounded))
        return self._rows("SELECT * FROM finding_retests WHERE assessment_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
                          (aid, bounded))

    def findings(self, aid=None):
        if aid:
            return self._rows(
                "SELECT * FROM findings WHERE assessment_id=? ORDER BY "
                "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,"
                " created_at DESC",
                (aid,),
            )
        return self._rows(
            "SELECT * FROM findings ORDER BY "
            "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,"
            " created_at DESC"
        )

    def severity_summary(self, aid):
        summary = {s: 0 for s in SEVERITIES}
        for row in self.findings(aid):
            summary[row["severity"]] = summary.get(row["severity"], 0) + 1
        return summary

    # ------------------------------------------------------------- AI analyses
    def save_ai_analysis(self, aid, kind, model, content, status="completed"):
        x = uid("AI")
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO ai_analyses (id,assessment_id,kind,model,content,created_at,status) VALUES (?,?,?,?,?,?,?)",
                (x, aid, kind, model, content, now(), status),
            )
        log.info("ai_analysis_saved", extra={"context": {"assessment_id": aid, "kind": kind, "model": model}})
        return self.ai_analysis(x)

    def ai_analysis(self, ai_id):
        row = self._one("SELECT * FROM ai_analyses WHERE id=?", (ai_id,))
        if row:
            try:
                row["content"] = json.loads(row["content"])
            except (ValueError, TypeError):
                pass
        return row

    def ai_analyses(self, aid=None, limit=25, kind=None):
        if aid and kind:
            rows = self._rows(
                "SELECT * FROM ai_analyses WHERE assessment_id=? AND kind=? "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (aid, kind, int(limit)),
            )
        elif aid:
            rows = self._rows(
                "SELECT * FROM ai_analyses WHERE assessment_id=? "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (aid, int(limit)),
            )
        elif kind:
            rows = self._rows(
                "SELECT * FROM ai_analyses WHERE assessment_id IS NULL AND kind=? "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (kind, int(limit)),
            )
        else:
            rows = self._rows(
                "SELECT * FROM ai_analyses ORDER BY created_at DESC, rowid DESC LIMIT ?", (int(limit),)
            )
        for row in rows:
            try:
                row["content"] = json.loads(row["content"])
            except (ValueError, TypeError):
                pass
        return rows

    # ----------------------------------------------------------------- summary
    def registry_counts(self):
        rows = self._rows("SELECT status, COUNT(*) AS n FROM assessments GROUP BY status")
        counts = {r["status"]: r["n"] for r in rows}
        counts["total"] = sum(counts.values())
        return counts

    def state(self, aid=None, include_all=False):
        if not aid:
            return {
                "assessment": None, "networks": [], "devices": [], "findings": [], "evidence": [],
                "events": [], "ai_analyses": [], "executions": [], "capture_imports": [],
                "wireless_defense_runs": [], "finding_retests": [],
                "severity_summary": self.severity_summary(None),
            }
        return {
            "assessment": self.assessment(aid),
            "networks": self.networks(aid),
            "devices": self.devices(aid),
            "findings": self.findings(aid),
            "evidence": self.evidence(aid, limit=1_000_000 if include_all else 200),
            "events": self.events(aid, limit=1_000_000 if include_all else 200),
            "ai_analyses": self.ai_analyses(aid, limit=1_000_000 if include_all else 25),
            "executions": self.executions(aid, limit=1_000_000 if include_all else 25),
            "capture_imports": self.capture_imports(aid, include_analysis=include_all),
            "wireless_defense_runs": self.wireless_defense_runs(aid, limit=1_000_000 if include_all else 100),
            "finding_retests": self.finding_retests(aid, limit=1_000_000 if include_all else 500),
            "severity_summary": self.severity_summary(aid),
        }

    # ---------------------------------------------------------------- settings
    def setting(self, key, default=""):
        row = self._one("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def settings(self):
        return {r["key"]: r["value"] for r in self._rows("SELECT key, value FROM settings")}

    def set_setting(self, key, value):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )


_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    target TEXT,
    environment TEXT,
    tester TEXT,
    authorization INTEGER NOT NULL DEFAULT 0,
    wireless_scope TEXT,
    network_scope TEXT,
    interface TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS executions(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    test_type TEXT NOT NULL,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    progress INTEGER NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    error TEXT,
    test_id TEXT,
    started_by TEXT
);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    execution_id TEXT,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS networks(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    ssid TEXT,
    bssid TEXT,
    channel INTEGER,
    frequency REAL,
    signal_pct INTEGER,
    signal_dbm REAL,
    auth TEXT,
    cipher TEXT,
    radio_type TEXT,
    observed_at TEXT,
    data_class TEXT,
    ssid_observed INTEGER,
    ssid_hidden INTEGER
);
CREATE TABLE IF NOT EXISTS devices(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    os TEXT,
    status TEXT,
    is_gateway INTEGER,
    is_self INTEGER,
    open_ports TEXT,
    device_type TEXT,
    interface TEXT,
    observed_at TEXT,
    data_class TEXT
);
CREATE TABLE IF NOT EXISTS device_discovery_runs(
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    interface TEXT,
    status TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    checked INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    results TEXT NOT NULL DEFAULT '[]',
    limitations TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    execution_id TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    source_test TEXT,
    detection_logic TEXT,
    recommendation TEXT,
    status TEXT NOT NULL,
    evidence_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_retests(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('fixed','partial','unresolved','unable_to_verify')),
    execution_id TEXT REFERENCES executions(id) ON DELETE SET NULL,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    execution_id TEXT,
    type TEXT,
    source TEXT,
    content TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_imports(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    source_sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    capture_format TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    parser_version TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    analysis_status TEXT NOT NULL,
    analysis TEXT NOT NULL,
    UNIQUE(assessment_id, source_sha256)
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_analyses(
    id TEXT PRIMARY KEY,
    assessment_id TEXT REFERENCES assessments(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    model TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observation_snapshots(
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    method TEXT NOT NULL,
    interface TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    observed_at TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    data_class TEXT NOT NULL DEFAULT 'live',
    results_json TEXT NOT NULL,
    limitations_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS wireless_defense_runs(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK(mode IN ('passive','simulation')),
    status TEXT NOT NULL,
    scope TEXT NOT NULL,
    ap_evidence_ref TEXT,
    targets_json TEXT NOT NULL,
    authorization_evidence_ref TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    result_json TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS wifi_audits(
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    model_version TEXT NOT NULL,
    score_status TEXT NOT NULL,
    score_value INTEGER,
    score_band TEXT,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wifi_audit_remediations(
    audit_id TEXT NOT NULL REFERENCES wifi_audits(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open','applied')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(audit_id,finding_id)
);
CREATE TABLE IF NOT EXISTS engagement_scopes(
    assessment_id TEXT PRIMARY KEY REFERENCES assessments(id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_change_history(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    changed_by TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_documents(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    document_format TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS authorization_document_history(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    document_id TEXT NOT NULL REFERENCES authorization_documents(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK(action IN ('attached','removed')),
    sha256 TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS training_sessions(
    id TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL,
    host TEXT NOT NULL CHECK(host='127.0.0.1'),
    port INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','stopped','expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ended_at TEXT
);
CREATE TABLE IF NOT EXISTS training_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES training_sessions(id) ON DELETE CASCADE,
    event TEXT NOT NULL CHECK(event IN ('visit','click','synthetic_response')),
    choice TEXT CHECK(choice IS NULL OR choice IN ('yes','no')),
    created_at TEXT NOT NULL,
    CHECK((event='synthetic_response' AND choice IS NOT NULL) OR (event!='synthetic_response' AND choice IS NULL))
);
"""


def _decode_wifi_audit(row):
    try:
        payload = json.loads(row.get("payload_json") or "")
    except (TypeError, ValueError):
        payload = None
    actual = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                      default=str).encode("utf-8")).hexdigest() if payload is not None else None
    return {**row, "payload": payload, "integrity_valid": bool(actual and actual == row.get("payload_sha256"))}


def _decode_device_discovery(row):
    for key in ("results", "limitations"):
        try:
            row[key] = json.loads(row.get(key) or ("[]" if key != "results" else "[]"))
        except (ValueError, TypeError):
            row[key] = []
    return row

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_exec_assessment ON executions(assessment_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_assessment ON events(assessment_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id, severity);
CREATE INDEX IF NOT EXISTS idx_finding_retests_assessment ON finding_retests(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_retests_finding ON finding_retests(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_assessment ON evidence(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_test ON evidence(assessment_id, test_id);
CREATE INDEX IF NOT EXISTS idx_networks_assessment ON networks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_devices_assessment ON devices(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ai_assessment ON ai_analyses(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_capture_imports_assessment ON capture_imports(assessment_id, imported_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_history_assessment ON scope_change_history(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authorization_documents_assessment ON authorization_documents(assessment_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_authorization_document_history_assessment ON authorization_document_history(assessment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_training_sessions_created ON training_sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_training_events_session ON training_events(session_id, id DESC);
"""
