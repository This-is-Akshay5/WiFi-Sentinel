"""Deterministic, evidence-linked correlation view.

This module deliberately does not infer exploit order. It creates support edges
only where a persisted finding directly references persisted evidence. Exact
asset-string overlap is exposed as a theoretical review candidate, not a path.
"""
from __future__ import annotations

import hashlib


def build_attack_path_graph(findings, evidence):
    evidence_by_id = {str(item.get("id")): item for item in evidence or [] if item and item.get("id")}
    unique_findings = {}
    for item in findings or []:
        if item and item.get("id"):
            unique_findings.setdefault(str(item["id"]), item)

    nodes = []
    edges = []
    supported_by_asset = {}
    used_evidence = set()

    for finding_id in sorted(unique_findings):
        finding = unique_findings[finding_id]
        asset = str(finding.get("asset") or "").strip()
        node = {
            "id": finding_id,
            "kind": "finding",
            "title": str(finding.get("title") or "Untitled finding"),
            "severity": str(finding.get("severity") or "Unknown"),
            "confidence": str(finding.get("confidence") or "Unknown"),
            "asset": asset,
            "status": str(finding.get("status") or "Unknown"),
            "evidence_id": str(finding.get("evidence_id") or ""),
            "observed_at": str(finding.get("created_at") or ""),
        }
        nodes.append(node)
        evidence_id = node["evidence_id"]
        if evidence_id and evidence_id in evidence_by_id:
            used_evidence.add(evidence_id)
            edges.append({"from": evidence_id, "to": finding_id, "relation": "supports",
                          "evidence_id": evidence_id})
            if asset:
                supported_by_asset.setdefault(asset.casefold(), {"asset": asset, "findings": []})
                supported_by_asset[asset.casefold()]["findings"].append(finding_id)

    evidence_nodes = []
    for evidence_id in sorted(used_evidence):
        item = evidence_by_id[evidence_id]
        evidence_nodes.append({
            "id": evidence_id,
            "kind": "evidence",
            "title": str(item.get("label") or item.get("type") or "Evidence"),
            "source": str(item.get("source") or "Not recorded"),
            "data_class": str(item.get("data_class") or "Not classified"),
            "observed_at": str(item.get("created_at") or ""),
        })
    nodes = evidence_nodes + nodes

    candidates = []
    for key in sorted(supported_by_asset):
        group = supported_by_asset[key]
        finding_ids = sorted(set(group["findings"]))
        if len(finding_ids) < 2:
            continue
        digest = hashlib.sha256((key + "\0" + "\0".join(finding_ids)).encode("utf-8")).hexdigest()[:12]
        candidates.append({
            "id": f"CORR-{digest.upper()}",
            "asset": group["asset"],
            "finding_ids": finding_ids,
            "evidence_ids": sorted({unique_findings[item].get("evidence_id") for item in finding_ids}),
            "classification": "theoretical",
            "basis": "Multiple evidence-backed findings use the same explicit asset string.",
            "ordered_exploit_chain_verified": False,
            "preconditions": ["Asset equivalence must be verified by the operator.",
                              "No exploit sequence or reachability is established by this correlation."],
        })

    return {
        "model_version": "evidence-correlation-v1",
        "assessment_scope": "persisted findings and evidence for one assessment",
        "nodes": nodes,
        "edges": edges,
        "correlation_candidates": candidates,
        "paths": [],
        "limitations": [
            "Support edges exist only for direct finding-to-evidence references.",
            "Exact asset-string overlap is a theoretical correlation candidate, not an exploit path.",
            "No ordered exploit chain is generated because the current evidence model stores no verified attack preconditions or transitions.",
        ],
    }
