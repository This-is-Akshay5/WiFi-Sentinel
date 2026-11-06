"""Assessment export payloads and a paginated PDF renderer."""
from __future__ import annotations

from datetime import datetime, timezone
import csv
import json
from xml.sax.saxutils import escape

from .posture import calculate as calculate_posture


def build_report(state, platform_context=None, generated_at=None):
    assessment = state.get("assessment") or {}
    executions = state.get("executions") or []
    counts = {name: sum(1 for row in executions if row.get("status") == name)
              for name in ("completed", "failed", "blocked", "cancelled", "running")}
    return {
        "report": {
            "product": "WiFiSentinel",
            "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "methodology": "Evidence-led assessment. Only persisted observations and execution records are reported. "
                           "Research corpus results remain separately labeled and do not represent live network traffic.",
            "execution_counts": counts,
            "coverage_limitations": sorted({
                str(row.get("error")) for row in executions if row.get("status") in {"blocked", "failed"} and row.get("error")
            }),
        },
        "platform_context": platform_context or {},
        "posture": calculate_posture(state),
        "assessment": assessment,
        "targets": {
            "target": assessment.get("target"),
            "wireless_scope": assessment.get("wireless_scope"),
            "network_scope": assessment.get("network_scope"),
            "interface": assessment.get("interface"),
        },
        "executions": executions,
        "networks": state.get("networks") or [],
        "devices": state.get("devices") or [],
        "findings": state.get("findings") or [],
        "evidence": state.get("evidence") or [],
        "capture_imports": state.get("capture_imports") or [],
        "wireless_defense_runs": state.get("wireless_defense_runs") or [],
        "finding_retests": state.get("finding_retests") or [],
        "observation_snapshots": state.get("observation_snapshots") or [],
        "authorization_documents": state.get("authorization_documents") or [],
        "authorization_document_history": state.get("authorization_document_history") or [],
        "events": state.get("events") or [],
        "ai_analyses": state.get("ai_analyses") or [],
        "severity_summary": state.get("severity_summary") or {},
    }


def write_json(path, report):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
    return str(path)


def write_findings_csv(path, findings, capture_imports=None, report_metadata=None, defense_runs=None,
                       observation_snapshots=None, finding_retests=None):
    """Export findings and capture provenance; neutralize spreadsheet formulas."""
    fields = ["record_type", "id", "title", "severity", "confidence", "description", "impact", "source_test",
              "detection_logic", "recommendation", "evidence_id", "asset", "category", "status",
              "created_at", "updated_at", "source_sha256", "capture_format", "size_bytes", "parser_version",
              "imported_at", "analysis_status", "stored_path", "report_methodology", "generated_at",
              "analysis_summary", "limitations", "mode", "scope", "targets", "data_class", "result",
              "source", "method", "interface", "first_seen", "last_seen", "observed_count"]
    def safe(value):
        text = str(value if value is not None else "")
        if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + text
        return text
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        records = [{**row, "record_type": "finding"} for row in findings]
        if report_metadata:
            records.insert(0, {"record_type": "report_metadata",
                               "report_methodology": report_metadata.get("methodology"),
                               "generated_at": report_metadata.get("generated_at"),
                               "limitations": json.dumps(report_metadata.get("coverage_limitations") or [], ensure_ascii=False)})
        records.extend({"record_type": "capture_import", "id": row.get("id"),
                        "title": row.get("filename"), "evidence_id": row.get("evidence_id"),
                        "status": row.get("analysis_status"), "source_sha256": row.get("source_sha256"),
                        "capture_format": row.get("capture_format"), "size_bytes": row.get("size_bytes"),
                        "parser_version": row.get("parser_version"), "imported_at": row.get("imported_at"),
                        "analysis_status": row.get("analysis_status"), "stored_path": row.get("stored_path"),
                        "analysis_summary": json.dumps({key: (row.get("analysis") or {}).get(key) for key in
                            ("packets_examined", "wireless_frames", "eapol_frames", "sae_authentication_frames",
                             "candidate_exchanges", "endpoint_count", "first_packet_timestamp", "last_packet_timestamp",
                             "frame_size_min_bytes", "frame_size_max_bytes", "wire_size_min_bytes", "wire_size_max_bytes",
                             "protocol_counts")}, ensure_ascii=False),
                        "limitations": json.dumps((row.get("analysis") or {}).get("limitations") or [], ensure_ascii=False)}
                       for row in (capture_imports or []))
        records.extend({"record_type":"wireless_defense_run","id":row.get("id"),"status":row.get("status"),
                        "mode":row.get("mode"),"scope":row.get("scope"),"targets":json.dumps(row.get("targets") or [],ensure_ascii=False),
                        "data_class":"simulation" if row.get("mode")=="simulation" else "capture",
                        "evidence_id":row.get("evidence_id"),"result":json.dumps(row.get("result") or {},ensure_ascii=False)}
                       for row in (defense_runs or []))
        records.extend({"record_type":"finding_retest","id":row.get("id"),"title":row.get("finding_id"),
                        "status":row.get("status"),"evidence_id":row.get("evidence_id"),
                        "created_at":row.get("created_at"),"result":json.dumps({"execution_id":row.get("execution_id"),
                        "detail":row.get("detail")},ensure_ascii=False)}
                       for row in (finding_retests or []))
        records.extend({"record_type":"observation_snapshot","id":row.get("id"),"status":row.get("status"),
                        "data_class":row.get("data_class"),"source":row.get("source"),"method":row.get("method"),
                        "interface":row.get("interface"),"first_seen":row.get("first_seen"),"last_seen":row.get("last_seen"),
                        "observed_count":len(row.get("results") or []),"limitations":json.dumps(row.get("limitations") or [],ensure_ascii=False)}
                       for row in (observation_snapshots or []))
        writer.writerows({key: safe(row.get(key, "")) for key in fields} for row in records)
    return str(path)


def write_pdf(path, report):
    """Render a real assessment report with wrapped tables and repeatable page furniture."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (Paragraph, Spacer, Table, LongTable, TableStyle,
                                    SimpleDocTemplate, PageBreak)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportSmall", parent=styles["BodyText"], fontSize=8, leading=10, spaceAfter=2))
    styles.add(ParagraphStyle(name="ReportCell", parent=styles["BodyText"], fontSize=7, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="ReportMeta", parent=styles["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#344054")))
    styles.add(ParagraphStyle(name="ReportFooter", parent=styles["BodyText"], fontSize=7, alignment=TA_CENTER, textColor=colors.grey))
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=20*mm, bottomMargin=18*mm, title="WiFiSentinel Security Assessment")
    dark = colors.HexColor("#20252b")
    story = []

    def para(value, style="BodyText"):
        return Paragraph(escape(str(value if value is not None else "—")), styles[style])

    def section(title):
        story.extend([Spacer(1, 7), Paragraph(escape(title), styles["Heading2"])])

    def table(headers, rows, widths):
        matrix = [[para(v, "ReportCell") for v in headers]]
        matrix.extend([[para(v, "ReportCell") for v in row] for row in rows] or [[para("No persisted records", "ReportCell")]+[para("", "ReportCell") for _ in headers[1:]]])
        result = LongTable(matrix, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), dark), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd2d9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        if headers and str(headers[0]).lower().startswith("severity"):
            severity_colors = {"critical": "#a00018", "high": "#b42332", "medium": "#855b00",
                               "low": "#245f83", "informational": "#58636d"}
            for index, row in enumerate(rows, start=1):
                severity = str(row[0] or "").split("/", 1)[0].strip().lower()
                if severity in severity_colors:
                    result.setStyle(TableStyle([("TEXTCOLOR", (0, index), (0, index), colors.HexColor(severity_colors[severity]))]))
        story.append(result)

    a = report.get("assessment") or {}
    posture = report.get("posture") or {}
    story.extend([Paragraph("WiFiSentinel Security Assessment", styles["Title"]),
                  para(f"{a.get('name', 'Assessment')} · {a.get('id', 'No ID')}", "Heading2"),
                  para(f"Generated: {report.get('report', {}).get('generated_at')} · Status: {a.get('status')}"),
                  Spacer(1, 8)])
    section("Scope and authorization")
    scope = report.get("targets") or {}
    table(["Field", "Value"], [[k.replace("_", " ").title(), v or "Not declared"] for k, v in scope.items()] + [
        ["Authorization", "Confirmed" if a.get("authorization") else "Not confirmed"],
        ["Authorized by", a.get("authorized_by") or "Not recorded"],
        ["Authorization reference", a.get("authorization_note") or "Not recorded"],
        ["Created", a.get("created_at")], ["Last execution", a.get("last_execution_at") or "None"],
    ], [42*mm, 132*mm])
    document_rows = report.get("authorization_documents") or []
    if document_rows:
        section("Authorization document records")
        table(["File", "Format", "Size", "SHA-256", "Attached", "By"], [
            [row.get("filename"), row.get("document_format"), row.get("size_bytes"), row.get("sha256"),
             row.get("uploaded_at"), row.get("uploaded_by")]
            for row in document_rows], [34*mm, 17*mm, 18*mm, 48*mm, 36*mm, 21*mm])
    document_history = report.get("authorization_document_history") or []
    if document_history:
        section("Authorization document change history")
        table(["Action", "Document", "SHA-256", "Changed by", "Time"], [
            [row.get("action"), row.get("document_id"), row.get("sha256"), row.get("changed_by"), row.get("created_at")]
            for row in document_history], [22*mm, 33*mm, 48*mm, 30*mm, 41*mm])
    section("Methodology and coverage")
    story.append(para(report.get("report", {}).get("methodology"), "ReportMeta"))
    counts = report.get("report", {}).get("execution_counts", {})
    table(["Execution status", "Count"], [[key.title(), value] for key, value in counts.items()], [132*mm, 42*mm])
    limitations = report.get("report", {}).get("coverage_limitations", [])
    for item in limitations:
        story.append(para("• " + item, "ReportSmall"))
    section("Security posture")
    story.append(para(f"{posture.get('score', '—')}/100 · {posture.get('grade', 'unavailable')} · {posture.get('interpretation', '')}", "ReportMeta"))
    story.append(para(f"Formula: {posture.get('formula', 'Unavailable')}", "ReportSmall"))
    for gap in posture.get("evidence_gaps", []):
        story.append(para("• " + gap, "ReportSmall"))
    section("Execution records")
    table(["Test", "Status", "Started", "Result / limitation"], [
        [x.get("test_type") or x.get("test_id"), x.get("status"), x.get("started_at"), x.get("error") or x.get("stage")]
        for x in report.get("executions", [])], [35*mm, 23*mm, 45*mm, 71*mm])
    section("Offline capture imports")
    capture_rows = report.get("capture_imports", [])
    table(["File / format", "Size / parser", "SHA-256", "Imported", "Evidence"], [
        [f"{x.get('filename')} / {x.get('capture_format')}", f"{x.get('size_bytes')} bytes / {x.get('parser_version')}",
         x.get("source_sha256"), x.get("imported_at"), x.get("evidence_id")]
        for x in capture_rows], [39*mm, 35*mm, 55*mm, 27*mm, 22*mm])
    for capture in capture_rows:
        analysis = capture.get("analysis") or {}
        summary = {key: analysis.get(key) for key in ("packets_examined", "wireless_frames", "eapol_frames",
                  "sae_authentication_frames", "candidate_exchanges", "endpoint_count", "first_packet_timestamp",
                  "last_packet_timestamp", "frame_size_min_bytes", "frame_size_max_bytes", "wire_size_min_bytes",
                  "wire_size_max_bytes", "protocol_counts")}
        story.append(para(f"{capture.get('filename')} analysis: " + json.dumps(summary, ensure_ascii=False, default=str), "ReportSmall"))
        summary = (capture.get("analysis") or {}).get("limitations") or []
        if summary:
            story.append(para(f"{capture.get('filename')} limitations: " + "; ".join(summary), "ReportSmall"))
    section("Observed networks")
    table(["SSID", "BSSID", "Channel", "Security", "Observed"], [
        [x.get("ssid") or ("Hidden SSID" if x.get("ssid_hidden") else "SSID unavailable"),
         x.get("bssid"), x.get("channel"), x.get("auth"), x.get("observed_at")]
        for x in report.get("networks", [])], [43*mm, 40*mm, 18*mm, 38*mm, 35*mm])
    section("Observed devices")
    table(["IP", "MAC", "Hostname", "Source / interface", "Observed"], [
        [x.get("ip"), x.get("mac"), x.get("hostname") or "Unresolved", x.get("interface") or "OS neighbor cache", x.get("observed_at")]
        for x in report.get("devices", [])], [30*mm, 37*mm, 35*mm, 40*mm, 32*mm])
    section("Wireless defense assessments")
    defense_rows = report.get("wireless_defense_runs", [])
    table(["Mode", "Status", "Scope", "Targets", "Evidence", "Completed"], [
        [x.get("mode"), x.get("status"), x.get("scope"), len(x.get("targets") or []), x.get("evidence_id"), x.get("completed_at")]
        for x in defense_rows], [18*mm, 24*mm, 42*mm, 15*mm, 35*mm, 40*mm])
    section("Source-labelled in-scope observation history")
    table(["Kind", "Source", "Method / interface", "Count", "First seen", "Last seen"], [
        [x.get("kind"), x.get("source"), f"{x.get('method')} / {x.get('interface') or 'Not reported'}",
         len(x.get("results") or []), x.get("first_seen"), x.get("last_seen")]
        for x in report.get("observation_snapshots", [])], [20*mm, 35*mm, 47*mm, 15*mm, 28*mm, 29*mm])
    section("Findings and remediation")
    table(["Severity / confidence", "Finding / asset", "Description / impact", "Recommendation / evidence"], [
        [f"{x.get('severity')} / {x.get('confidence')}", f"{x.get('title')}\nAsset: {x.get('asset') or 'Not specified'}",
         f"{x.get('description')}\nImpact: {x.get('impact')}",
         f"{x.get('recommendation')}\nEvidence ID: {x.get('evidence_id') or 'None'}"]
        for x in report.get("findings", [])], [34*mm, 42*mm, 49*mm, 49*mm])
    section("Finding retest history")
    table(["Finding", "Outcome", "Execution", "New evidence", "Time / detail"], [
        [x.get("finding_id"), x.get("status"), x.get("execution_id"), x.get("evidence_id"),
         f"{x.get('created_at')}\n{x.get('detail')}" ]
        for x in report.get("finding_retests", [])], [27*mm, 24*mm, 34*mm, 34*mm, 55*mm])
    section("Evidence references")
    table(["ID", "Type / source", "Classification", "Observed", "Label"], [
        [x.get("id"), f"{x.get('type')} / {x.get('source')}", x.get("data_class"), x.get("created_at"), x.get("label")]
        for x in report.get("evidence", [])], [25*mm, 55*mm, 28*mm, 38*mm, 28*mm])
    section("AI analysis and interpretation")
    ai_rows = report.get("ai_analyses", [])
    for ai in ai_rows:
        content = ai.get("content") or {}
        story.append(para(f"{ai.get('kind')} · {ai.get('model')} · {ai.get('created_at')}", "Heading3"))
        if isinstance(content, dict):
            for key, value in content.items():
                story.append(para(key.replace("_", " ").title(), "Heading4"))
                if isinstance(value, list):
                    story.extend(para("• " + item, "ReportSmall") for item in value)
                else:
                    story.append(para(value, "ReportSmall"))
        else:
            story.append(para("Stored structured analysis; see the JSON export for all fields."))
        story.append(Spacer(1, 4))
    if not ai_rows:
        story.append(para("No AI analysis is stored for this assessment."))
    section("Platform and limitations")
    for key, value in (report.get("platform_context") or {}).items():
        story.append(para(f"{key.replace('_', ' ').title()}: {value}", "ReportSmall"))
    story.append(para("OS scan coverage depends on the active adapter, supported bands/channels, operating-system APIs, and permissions. Neighbor-cache entries do not prove a device is currently online. An empty scan or cache is not proof of absence. Research-corpus records are not live network observations. User-supplied PCAP analysis is offline evidence and does not represent live capture or prove capture completeness.", "ReportSmall"))

    def furniture(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(colors.HexColor("#344054"))
        canvas.drawString(16*mm, A4[1]-12*mm, "WIFISENTINEL · SECURITY ASSESSMENT")
        canvas.setStrokeColor(colors.HexColor("#cbd2d9"))
        canvas.line(16*mm, 14*mm, A4[0]-16*mm, 14*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(16*mm, 9*mm, "WiFiSentinel · Confidential assessment record")
        canvas.drawRightString(A4[0]-16*mm, 9*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=furniture, onLaterPages=furniture)
    return str(path)


def write_wifi_audit_pdf(path, audit):
    """Render only an integrity-verified, persisted Wi-Fi audit payload."""
    if not isinstance(audit, dict) or audit.get("integrity_valid") is not True:
        raise ValueError("A persisted Wi-Fi audit with a valid integrity digest is required.")
    payload = audit.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Wi-Fi audit payload is unavailable.")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import (Paragraph, Spacer, LongTable, TableStyle,
                                    SimpleDocTemplate)

    styles = getSampleStyleSheet()
    if "STSong-Light" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    styles.add(ParagraphStyle(name="AuditSmall", parent=styles["BodyText"], fontName="STSong-Light", fontSize=8, leading=10, spaceAfter=3))
    styles.add(ParagraphStyle(name="AuditCell", parent=styles["BodyText"], fontName="STSong-Light", fontSize=7, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="AuditMeta", parent=styles["BodyText"], fontSize=9, leading=12,
                              fontName="STSong-Light", textColor=colors.HexColor("#344054")))
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=20*mm, bottomMargin=18*mm, title="WiFiSentinel Wi-Fi Security Audit")
    story = []

    def para(value, style="BodyText"):
        return Paragraph(escape(str(value if value not in (None, "") else "Not reported")), styles[style])

    def section(title):
        story.extend([Spacer(1, 7), Paragraph(escape(title), styles["Heading2"])])

    def table(headers, rows, widths):
        matrix = [[para(value, "AuditCell") for value in headers]]
        matrix.extend([[para(value, "AuditCell") for value in row] for row in rows] or
                      [[para("No persisted records", "AuditCell") for _ in headers]])
        output = LongTable(matrix, colWidths=widths, repeatRows=1, hAlign="LEFT")
        output.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#20252b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd2d9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(output)

    network = payload.get("network") or {}
    score = payload.get("score") or {}
    coverage = payload.get("coverage") or {}
    story.extend([Paragraph("WiFiSentinel Wi-Fi Security Audit", styles["Title"]),
                  para(f"Assessment {audit.get('id')} · {payload.get('created_at') or audit.get('created_at')}", "Heading2"),
                  para(f"Scope: {payload.get('scope')} · Status: {payload.get('status')}"), Spacer(1, 7)])
    section("Observed network context")
    table(["Field", "Observed value"], [
        ["SSID", network.get("ssid") or ("SSID reported hidden" if network.get("ssid_hidden") else "Not reported")], ["BSSID", network.get("bssid") or "Not reported"],
        ["Interface", network.get("interface") or "Not reported"], ["Connection state", network.get("connection_state")],
        ["Local IP / subnet", f"{network.get('local_ip') or 'Not reported'} / {network.get('subnet') or 'Not reported'}"],
        ["Gateway", network.get("gateway") or "Not reported"], ["Authentication / cipher", f"{network.get('authentication') or 'Not reported'} / {network.get('cipher') or 'Not reported'}"],
        ["Band / channel / signal", f"{network.get('band') or 'Not reported'} GHz / {network.get('channel') or 'Not reported'} / {network.get('signal_dbm') or 'Not reported'} dBm"],
        ["Source / observation", f"{network.get('source') or payload.get('source')} / {network.get('observed_at') or payload.get('observed_at')}"],
        ["Authorization", "Operator confirmed for this audit" if payload.get("authorization_confirmed") else "Not confirmed"],
    ], [42*mm, 132*mm])

    section("Risk, model, and coverage")
    if score.get("status") == "scored":
        story.append(para(f"Risk score: {score.get('value')}/100 · {score.get('band')} · model {score.get('model_version')}", "AuditMeta"))
    else:
        story.append(para(f"Risk score: Insufficient evidence · {score.get('reason') or 'Required evidence was unavailable.'}", "AuditMeta"))
    story.append(para(f"Formula: {score.get('formula') or 'Not available'}", "AuditSmall"))
    for factor, rationale in (score.get("factor_rationale") or {}).items():
        story.append(para(f"{factor.replace('_', ' ').title()}: {rationale}", "AuditSmall"))
    story.append(para(f"Product-defined bands (not an industry standard): {json.dumps(score.get('risk_band_thresholds') or {}, ensure_ascii=False)}", "AuditSmall"))
    story.append(para(f"Coverage: {coverage.get('checks_observed', 0)} of {coverage.get('checks_total', 0)} checks produced observations; {coverage.get('core_checks_observed', 0)} of {coverage.get('core_checks_total', 0)} core checks produced evidence.", "AuditSmall"))
    story.append(para(score.get("note") or "", "AuditSmall"))

    section("Checks and evidence")
    table(["Check / status", "Result and source evidence"], [
        [f"{check.get('label')} / {check.get('status')}",
         f"{check.get('detail')}\nEvidence: {json.dumps(check.get('evidence'), ensure_ascii=False, default=str) if check.get('evidence') else 'Not available'}"]
        for check in payload.get("checks", [])], [54*mm, 120*mm])

    section("Evidence-backed findings")
    findings = payload.get("findings", [])
    score_contributions = {str(item.get("check_id")): item for item in score.get("contributions", [])}
    table(["Severity / confidence", "Finding", "Evidence and impact", "Remediation / verification"], [
        [f"{finding.get('severity')} / {finding.get('confidence')}",
         f"{finding.get('title')}\n{finding.get('description')}",
         f"Source: {finding.get('source')} · {finding.get('observed_at')}\n{json.dumps(finding.get('evidence') or {}, ensure_ascii=False, default=str)}\nImpact: {finding.get('impact')}",
         f"{finding.get('recommendation')}\nVerification: {finding.get('verification')}\nRisk contribution: {score_contributions.get(str(finding.get('check_id')), {}).get('contribution', 'Not scored')} points\nIncluded in score: {score_contributions.get(str(finding.get('check_id')), {}).get('included_in_score', 'Not scored')}\nRisk factors: {json.dumps(finding.get('risk_factors') or {}, ensure_ascii=False, default=str)}"]
        for finding in findings], [30*mm, 44*mm, 50*mm, 50*mm])
    section("Prioritized remediation")
    table(["Priority", "Action", "Verification / status"], [
        [item.get("priority"), item.get("action"),
         f"{item.get('verification')} / {next((row.get('status') for row in audit.get('remediations', []) if row.get('finding_id') == item.get('finding_id')), item.get('status'))}"]
        for item in payload.get("recommendations", [])], [20*mm, 78*mm, 76*mm])
    verification_rows = payload.get("remediation_verification", []) or []
    if verification_rows:
        section("Verification of previously applied remediation")
        table(["Finding", "Result", "Time / evidence"], [
            [item.get("title") or item.get("check_id"), item.get("status"),
             f"{item.get('verified_at')}\n{item.get('detail')}\n{json.dumps(item.get('evidence') or {}, ensure_ascii=False, default=str)}"]
            for item in verification_rows], [48*mm, 34*mm, 92*mm])
    section("Limitations and manual verification")
    for limit in payload.get("limitations", []) or ["No additional limitations were recorded."]:
        story.append(para("• " + str(limit), "AuditSmall"))
    story.append(para("Observed values are reported as returned by the operating system. Unknown controls are not treated as passed. Router settings require owner-side verification. WiFiSentinel does not retrieve saved Wi-Fi passwords, include packet payloads, or change router configuration.", "AuditSmall"))
    story.append(para(f"Method: {payload.get('methodology')}", "AuditSmall"))

    def furniture(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(colors.HexColor("#344054"))
        canvas.drawString(16*mm, A4[1]-12*mm, "WIFISENTINEL · WI-FI SECURITY AUDIT")
        canvas.setStrokeColor(colors.HexColor("#cbd2d9"))
        canvas.line(16*mm, 14*mm, A4[0]-16*mm, 14*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(16*mm, 9*mm, f"Audit {audit.get('id')} · Persisted evidence")
        canvas.drawRightString(A4[0]-16*mm, 9*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=furniture, onLaterPages=furniture)
    return str(path)
