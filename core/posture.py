"""Deterministic security posture.

The score is arithmetic, never opinion. Every number that goes into it comes
from persisted findings, executed tests and stored evidence, and every
component is returned alongside its inputs so the UI can show the arithmetic
instead of asking anyone to trust a score.

AI may explain this result. AI may not change it.
"""
from __future__ import annotations

from .catalog import TEST_CATALOG
from .store import SEVERITY_WEIGHTS

#: Score is a 0-100 index. Deductions are bounded so a large environment cannot
#: drive the index negative, and coverage can never push it above 100.
MAX_SCORE = 100
COVERAGE_CAP = 100


def _grade(score):
    if score >= 85:
        return "strong"
    if score >= 70:
        return "acceptable"
    if score >= 50:
        return "weak"
    if score >= 30:
        return "poor"
    return "critical"


def calculate(state, catalog_state=None):
    """Compute the posture index for one assessment state.

    ``state`` is :meth:`core.store.Store.state` output for a single assessment.
    ``catalog_state`` is the Security Tests tab payload, used for coverage.
    """
    assessment = state.get("assessment") or {}
    findings = state.get("findings") or []
    evidence = state.get("evidence") or []
    executions = state.get("executions") or []

    severity_counts = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1

    # 1. Finding pressure -----------------------------------------------------
    raw_penalty = 0.0
    penalty_detail = {}
    for severity, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        contribution = weight * count
        penalty_detail[severity] = contribution
        raw_penalty += contribution
    finding_score = max(0.0, MAX_SCORE - raw_penalty)

    # 2. Test coverage --------------------------------------------------------
    applicable = [t for t in TEST_CATALOG if t["execution_path"] == "local"]
    executed_ids = set()
    blocked_ids = set()
    for execution in executions:
        test_id = execution.get("test_id")
        if not test_id:
            continue
        if execution.get("status") == "completed":
            executed_ids.add(test_id)
        elif execution.get("status") in ("blocked", "failed"):
            blocked_ids.add(test_id)
    applicable_ids = {t["id"] for t in applicable}
    covered = len(applicable_ids & (executed_ids | blocked_ids))
    total_applicable = len(applicable_ids)
    coverage_ratio = covered / total_applicable if total_applicable else 0.0
    coverage_score = coverage_ratio * COVERAGE_CAP

    # 3. Evidence quality -----------------------------------------------------
    live_evidence = [e for e in evidence if e.get("data_class") in (None, "live")]
    capture_evidence = [e for e in evidence if e.get("data_class") == "capture"]
    research_evidence = [e for e in evidence if e.get("data_class") == "research"]
    linked = sum(1 for f in findings if f.get("evidence_id"))
    link_ratio = linked / len(findings) if findings else 1.0
    evidence_score = min(100.0, len(evidence) * 6.0 + link_ratio * 40.0)

    composite = round(
        0.55 * finding_score + 0.25 * coverage_score + 0.20 * evidence_score
    )
    composite = max(0, min(MAX_SCORE, composite))

    gaps = []
    if not authorization_blocked(assessment):
        gaps.append("Authorization is not confirmed; execution remains blocked.")
    unexecuted = sorted(applicable_ids - (executed_ids | blocked_ids))
    if unexecuted:
        gaps.append(f"{len(unexecuted)} locally supported test(s) have not been executed: {', '.join(unexecuted)}.")
    if not findings and executed_ids:
        gaps.append("Tests executed so far produced no findings from observed evidence.")
    if not evidence:
        gaps.append("No evidence has been persisted for this assessment.")
    if research_evidence and not live_evidence:
        gaps.append("Only research-dataset evidence exists; no live telemetry has been collected.")
    if capture_evidence and not live_evidence and not research_evidence:
        gaps.append("Only user-supplied offline capture evidence exists; no live OS telemetry has been collected.")

    return {
        "score": composite,
        "max_score": MAX_SCORE,
        "grade": _grade(composite),
        "authorization_recorded": bool(assessment.get("authorization")),
        "assessment_status": assessment.get("status"),
        "computed_from": {
            "findings_total": len(findings),
            "findings_by_severity": severity_counts,
            "finding_penalty_points": penalty_detail,
            "finding_subscore": round(finding_score, 1),
            "tests_applicable_locally": total_applicable,
            "tests_covered": covered,
            "coverage_ratio": round(coverage_ratio, 3),
            "coverage_subscore": round(coverage_score, 1),
            "evidence_total": len(evidence),
            "evidence_live": len(live_evidence),
            "evidence_capture": len(capture_evidence),
            "evidence_research": len(research_evidence),
            "findings_linked_to_evidence": linked,
            "evidence_link_ratio": round(link_ratio, 3),
            "evidence_subscore": round(evidence_score, 1),
        },
        "formula": "0.55 x finding subscore + 0.25 x coverage subscore + 0.20 x evidence subscore",
        "executed_tests": sorted(executed_ids),
        "blocked_tests": sorted(blocked_ids),
        "pending_tests": unexecuted,
        "evidence_gaps": gaps,
        "interpretation": "Deterministic index computed from persisted findings, executed test coverage and stored evidence. "
                          "It is a reporting aid, not a compliance certification, and it is not modified by AI analysis.",
    }


def authorization_blocked(assessment):
    return not (assessment or {}).get("authorization")
