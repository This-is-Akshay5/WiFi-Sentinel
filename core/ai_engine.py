"""Evidence-grounded OpenAI analysis layer.

Contract
--------
* The model only ever sees evidence that WiFiSentinel already collected and
  persisted. It cannot query the machine and it is never asked to guess.
* Every call uses the OpenAI **Responses API** with a strict JSON schema, and the
  response is validated before it is rendered. Malformed output produces an error
  state, never a half-rendered card.
* Each result is normalized into the same envelope so the UI can label every
  statement by kind: ``observed`` / ``derived`` / ``interpreted`` /
  ``recommended``.
* The API key is read from ``OPENAI_API_KEY``, held in memory only, and is never
  written to SQLite, logged, or exposed to JavaScript.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .logging_setup import get_logger, secret_fingerprint

log = get_logger("ai")

#: Default model used when ``OPENAI_MODEL`` is not set. Override per deployment.
DEFAULT_MODEL = "gpt-6-luna"
ENDPOINT = "https://api.openai.com/v1/responses"
MAX_OUTPUT_TOKENS = 4000

OBSERVED = "OBSERVED"
DERIVED = "DERIVED"
INTERPRETED = "INTERPRETED"
RECOMMENDED = "RECOMMENDED"

#: Field lists per analysis kind. Each entry maps to exactly one statement class.
ENVELOPE_FIELDS = {
    "dataset": {
        "executive_summary": INTERPRETED,
        "key_observations": OBSERVED,
        "behavioral_signals": DERIVED,
        "device_priorities": DERIVED,
        "validation_actions": RECOMMENDED,
        "limitations": OBSERVED,
    },
    "assessment": {
        "executive_summary": INTERPRETED,
        "security_posture": INTERPRETED,
        "confirmed_observations": OBSERVED,
        "risk_themes": DERIVED,
        "priority_actions": RECOMMENDED,
        "coverage_gaps": OBSERVED,
        "confidence_note": INTERPRETED,
    },
    "finding": {
        "explanation": INTERPRETED,
        "confidence": INTERPRETED,
        "false_positive_considerations": DERIVED,
        "remediation": RECOMMENDED,
        "validation_steps": RECOMMENDED,
    },
    "posture": {
        "summary": INTERPRETED,
        "strengths": DERIVED,
        "risk_themes": DERIVED,
        "prioritized_actions": RECOMMENDED,
        "evidence_gaps": OBSERVED,
    },
    "report": {
        "executive_summary": INTERPRETED,
        "scope_and_methodology": OBSERVED,
        "key_findings": OBSERVED,
        "recommended_actions": RECOMMENDED,
        "limitations": OBSERVED,
        "closing_summary": INTERPRETED,
    },
}

#: Confidence accepted for a structured response, mapped to a bounded score.
_CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.6, "low": 0.3}


def _string_array(description):
    return {"type": "array", "description": description, "items": {"type": "string"}}


SCHEMAS = {
    "dataset": {
        "type": "object", "additionalProperties": False,
        "description": "Analysis of a supplied association/disassociation research corpus.",
        "properties": {
            "executive_summary": {"type": "string", "description": "Concise interpretation of the supplied statistics."},
            "key_observations": _string_array("Statistics that are present in the supplied input."),
            "behavioral_signals": _string_array("Behavioural patterns derived from those statistics."),
            "device_priorities": _string_array("Devices that stand out in the supplied per-device data."),
            "validation_actions": _string_array("Defensive steps to validate the interpretation."),
            "limitations": _string_array("What the dataset cannot show."),
        },
        "required": ["executive_summary", "key_observations", "behavioral_signals", "device_priorities",
                     "validation_actions", "limitations"],
    },
    "assessment": {
        "type": "object", "additionalProperties": False,
        "description": "Synthesis of one authorized assessment from its persisted evidence.",
        "properties": {
            "executive_summary": {"type": "string"},
            "security_posture": {"type": "string", "description": "Explanation of the deterministic posture inputs."},
            "confirmed_observations": _string_array("Findings and evidence that were actually recorded."),
            "risk_themes": _string_array("Themes grouping the recorded findings."),
            "priority_actions": _string_array("Ordered defensive actions."),
            "coverage_gaps": _string_array("Tests or telemetry that were unavailable."),
            "confidence_note": {"type": "string"},
        },
        "required": ["executive_summary", "security_posture", "confirmed_observations", "risk_themes",
                     "priority_actions", "coverage_gaps", "confidence_note"],
    },
    "finding": {
        "type": "object", "additionalProperties": False,
        "description": "Review of a single evidence-linked finding.",
        "properties": {
            "explanation": {"type": "string"},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "false_positive_considerations": _string_array("Benign explanations that must be ruled out."),
            "remediation": _string_array("Concrete remediation steps."),
            "validation_steps": _string_array("How to confirm the remediation worked."),
        },
        "required": ["explanation", "confidence", "false_positive_considerations", "remediation", "validation_steps"],
    },
    "posture": {
        "type": "object", "additionalProperties": False,
        "description": "Explanation of a deterministic posture calculation.",
        "properties": {
            "summary": {"type": "string"},
            "strengths": _string_array("Controls evidenced by the assessment."),
            "risk_themes": _string_array("Themes that drove the posture score down."),
            "prioritized_actions": _string_array("Actions that would most improve the score."),
            "evidence_gaps": _string_array("Missing evidence that limits confidence."),
        },
        "required": ["summary", "strengths", "risk_themes", "prioritized_actions", "evidence_gaps"],
    },
    "report": {
        "type": "object", "additionalProperties": False,
        "description": "Management-facing executive report.",
        "properties": {
            "executive_summary": {"type": "string"},
            "scope_and_methodology": {"type": "string"},
            "key_findings": _string_array("Findings that were actually recorded."),
            "recommended_actions": _string_array("Prioritised remediation."),
            "limitations": _string_array("What the assessment could not establish."),
            "closing_summary": {"type": "string"},
        },
        "required": ["executive_summary", "scope_and_methodology", "key_findings", "recommended_actions",
                     "limitations", "closing_summary"],
    },
}

SYSTEM_PROMPTS = {
    "dataset": (
        "You are the defensive analytics component of a wireless security assessment platform. "
        "You receive statistics computed from a supplied research corpus of association/disassociation events. "
        "Treat every statement as research evidence about that corpus only. Never claim it is live traffic, never "
        "invent packet fields, SSIDs, vendors, devices, attacks or certainty that is not in the input, and never "
        "state a device count or a port that the input does not contain. Recommendations must be defensive and "
        "within an authorized assessment."
    ),
    "assessment": (
        "You are a defensive wireless security analyst reviewing one authorized assessment. "
        "Work only from the evidence and findings supplied. Separate live OS observations, user-supplied offline "
        "capture evidence, research-corpus evidence and your own interpretation. An offline capture is not live "
        "telemetry. Never invent telemetry, never claim a test succeeded when it "
        "was blocked, and never describe an attack technique as executed. Be concrete and defensible."
    ),
    "finding": (
        "You are a defensive finding-review assistant. Explain the supplied persisted finding using only its "
        "fields and its linked evidence. Assess confidence qualitatively, list benign explanations that must be "
        "ruled out, and give concrete remediation and validation steps. Never fabricate evidence and never provide "
        "attack instructions."
    ),
    "posture": (
        "You are a defensive wireless security posture analyst. Explain the deterministic posture calculation "
        "supplied to you and the evidence behind it. You may not change or re-score the posture; you may only "
        "explain it. Identify evidence gaps without guessing at their contents."
    ),
    "report": (
        "You write an evidence-grounded executive security assessment report. Use only the supplied assessment "
        "state. Distinguish live observations, user-supplied offline capture evidence, research-corpus evidence and "
        "AI interpretation. Never claim offline capture review was a live test. Never fabricate "
        "testing, vulnerabilities, affected systems, exploitability or remediation results. Keep the language "
        "concise and professional."
    ),
}


class AIEngine:
    def __init__(self, model=None, api_key=None, timeout=60):
        self.api_key = (api_key if api_key is not None else os.getenv("OPENAI_API_KEY", "")).strip()
        self.model = (model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)).strip() or DEFAULT_MODEL
        self.timeout = timeout

    # ------------------------------------------------------------------ status
    def status(self):
        return {
            "configured": bool(self.api_key),
            "credential": secret_fingerprint(self.api_key),
            "model": self.model,
            "provider": "OpenAI",
            "api": "Responses API",
            "endpoint": ENDPOINT,
            "timeout_seconds": self.timeout,
            "capabilities": ["dataset_analysis", "assessment_analysis", "finding_review",
                             "posture_explanation", "executive_report"],
        }

    def reload(self):
        """Re-read credentials from the environment (used after a Settings change)."""
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
        return self.status()

    # ---------------------------------------------------------------- transport
    @staticmethod
    def _extract_text(response):
        if isinstance(response, dict):
            direct = response.get("output_text")
            if isinstance(direct, str) and direct.strip():
                return direct
            chunks = []
            for item in response.get("output") or []:
                for content in item.get("content") or []:
                    if isinstance(content, dict) and isinstance(content.get("text"), str):
                        chunks.append(content["text"])
            return "\n".join(chunks).strip()
        return ""

    def _failure(self, error, code, detail=None):
        secret = self.api_key
        if secret:
            error = str(error).replace(secret, "[redacted]")
            detail = str(detail or "").replace(secret, "[redacted]")
        log.warning("ai_call_failed", extra={"context": {"code": code, "detail": (detail or "")[:200]}})
        return {"ok": False, "error": error, "error_code": code, "status": self.status()}

    def _call(self, kind, payload):
        if not self.api_key:
            return self._failure(
                "AI is unavailable: OPENAI_API_KEY is not configured. Copy .env.example to .env and set the key.",
                "not_configured",
            )
        body = {
            "model": self.model,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": SYSTEM_PROMPTS[kind]}]},
                {"role": "user", "content": [{"type": "input_text",
                                              "text": json.dumps(payload, ensure_ascii=False, default=str)}]},
            ],
            "text": {"format": {"type": "json_schema", "name": f"wifisentinel_{kind}",
                                "strict": True, "schema": SCHEMAS[kind]}},
            "max_output_tokens": MAX_OUTPUT_TOKENS,
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload_out = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = _read_error(exc)
            return self._failure(f"OpenAI API error (HTTP {exc.code}). {_explain_http(exc.code, detail)}",
                                 _http_code_class(exc.code), detail)
        except (urllib.error.URLError, TimeoutError) as exc:
            return self._failure(f"AI is unavailable: the OpenAI request failed to complete ({exc}).",
                                 "network_error", str(exc))
        except json.JSONDecodeError:
            return self._failure("AI is unavailable: OpenAI returned a malformed response.", "malformed_response")
        except Exception as exc:
            return self._failure(f"AI request failed: {type(exc).__name__}.", "request_error", str(exc))

        text = self._extract_text(payload_out)
        if not text:
            return self._failure("AI is unavailable: OpenAI returned no analysis content.", "empty_response")
        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            return self._failure(f"AI response failed validation: invalid structured JSON ({exc}).",
                                 "malformed_response")
        validation = validate_result(kind, result)
        if not validation["valid"]:
            return self._failure(
                "AI response failed validation: " + "; ".join(validation["errors"]),
                "schema_violation",
            )
        log.info("ai_call_succeeded", extra={"context": {"kind": kind, "model": self.model}})
        return {
            "ok": True,
            "kind": kind,
            "result": result,
            "model": payload_out.get("model") or self.model,
            "usage": payload_out.get("usage"),
            "envelope": build_envelope(kind, result),
            "status": self.status(),
        }

    # ------------------------------------------------------------- entry points
    def dataset(self, analysis, detection):
        return self._call("dataset", {"corpus_analysis": analysis, "deterministic_detection": detection})

    def assessment(self, state, posture=None):
        return self._call("assessment", {"assessment_state": state, "deterministic_posture": posture})

    def finding(self, finding, evidence):
        return self._call("finding", {"finding": finding, "linked_evidence": evidence})

    def posture(self, state, posture=None):
        return self._call("posture", {"assessment_state": state, "deterministic_posture": posture})

    def report(self, state, posture=None):
        return self._call("report", {"assessment_state": state, "deterministic_posture": posture})


# ------------------------------------------------------------------ validation
def validate_result(kind, result):
    """Validate a structured AI response before it is rendered or persisted."""
    schema = SCHEMAS.get(kind)
    errors = []
    if schema is None:
        return {"valid": False, "errors": [f"Unknown analysis kind: {kind}"]}
    if not isinstance(result, dict):
        return {"valid": False, "errors": ["Response is not a JSON object."]}
    for field in schema["required"]:
        if field not in result:
            errors.append(f"missing field: {field}")
    for field, spec in schema["properties"].items():
        if field not in result:
            continue
        value = result[field]
        if spec["type"] == "string" and not isinstance(value, str):
            errors.append(f"{field} must be a string")
        elif spec["type"] == "array":
            if not isinstance(value, list):
                errors.append(f"{field} must be an array")
            elif not all(isinstance(item, str) for item in value):
                errors.append(f"{field} must contain only strings")
        if "enum" in spec and isinstance(value, str) and value.lower() not in spec["enum"]:
            errors.append(f"{field} must be one of {spec['enum']}")
    if kind == "finding" and isinstance(result.get("confidence"), str):
        if result["confidence"].strip().lower() not in _CONFIDENCE_SCORES:
            errors.append("confidence must be high, medium or low")
    return {"valid": not errors, "errors": errors}


def build_envelope(kind, result):
    """Normalize a validated response into the labelled statement envelope."""
    fields = ENVELOPE_FIELDS.get(kind, {})
    envelope = {"summary": "", "observed": [], "derived": [], "interpreted": [], "recommended": [],
                "evidence": [], "risk": None, "confidence": None, "limitations": [], "statements": []}
    for field, statement_class in fields.items():
        value = result.get(field)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = item.strip() if isinstance(item, str) else str(item)
            if not text:
                continue
            envelope["statements"].append({"field": field, "class": statement_class, "text": text})
            bucket = statement_class.lower()
            if bucket in envelope:
                envelope[bucket].append(text)
    envelope["summary"] = (result.get("executive_summary") or result.get("summary")
                          or result.get("explanation") or "")
    envelope["evidence"] = [s["text"] for s in envelope["statements"] if s["field"] == "confirmed_observations"] \
        or [s["text"] for s in envelope["statements"] if s["field"] == "key_observations"]
    envelope["limitations"] = [s["text"] for s in envelope["statements"] if s["field"] in ("limitations", "coverage_gaps", "evidence_gaps")]
    envelope["risk"] = result.get("security_posture") or (
        result.get("risk_themes")[0] if isinstance(result.get("risk_themes"), list) and result["risk_themes"] else None)
    confidence = result.get("confidence")
    if isinstance(confidence, str) and confidence.strip():
        envelope["confidence"] = {"label": confidence.strip().lower(),
                                  "score": _CONFIDENCE_SCORES.get(confidence.strip().lower())}
    else:
        envelope["confidence"] = {"label": "qualitative", "score": None,
                                  "note": result.get("confidence_note") or ""}
    envelope["attribution"] = "AI interpretation of persisted evidence. Not telemetry and not an OS observation."
    return envelope


# --------------------------------------------------------------------- errors
def _read_error(exc):
    try:
        return exc.read().decode("utf-8", "replace")[:2000]
    except Exception:
        return ""


def _http_code_class(code):
    if code in (401, 403):
        return "authentication_error"
    if code == 429:
        return "quota_or_rate_limit"
    if code == 400:
        return "bad_request"
    if code >= 500:
        return "provider_error"
    return "http_error"


def _explain_http(code, detail):
    message = ""
    try:
        parsed = json.loads(detail)
        message = str(parsed.get("error", {}).get("message") or "")
    except Exception:
        message = (detail or "")[:160]
    if code in (401, 403):
        return "OPENAI_API_KEY was rejected. Verify the key and that it has access to the selected model."
    if code == 429:
        return "The account is rate limited or out of quota. Check OpenAI billing/usage limits."
    if code == 404:
        return f"Model '{DEFAULT_MODEL}' or the configured model is unavailable for this key."
    if code >= 500:
        return "OpenAI reported a server-side failure. Retry later."
    return message or f"The request was rejected (HTTP {code})."
