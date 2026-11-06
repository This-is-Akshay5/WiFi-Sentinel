(function (root, factory) {
  const view = factory();
  if (typeof module === 'object' && module.exports) module.exports = view;
  if (root) root.WiFiSentinelAuditView = view;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const reported = value => value === undefined || value === null || value === '' ? 'Not reported' : esc(value);
  const chip = status => `<span class="badge audit-status audit-${esc(String(status || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '-'))}">${reported(status)}</span>`;
  const metric = (label, value) => `<div class="audit-metric"><span>${esc(label)}</span><b>${reported(value)}</b></div>`;

  function render(options = {}) {
    const snapshot = options.snapshot || {};
    const wifi = snapshot.wifi || {};
    const network = snapshot.network || {};
    const active = options.active && options.active.payload ? options.active : null;
    const payload = active ? active.payload : null;
    const auditNetwork = payload ? (payload.network || {}) : null;
    const score = payload ? (payload.score || {}) : null;
    const coverage = payload ? (payload.coverage || {}) : null;
    const identity = auditNetwork || {
      ssid: wifi.ssid, ssid_hidden: wifi.ssid_hidden === true, bssid: wifi.bssid, interface: wifi.interface || network.interface,
      connection_state: wifi.connected === true ? 'connected' : (wifi.state || 'unknown'),
      local_ip: network.local_ip, subnet: network.network, gateway: network.gateway,
      authentication: wifi.auth, cipher: wifi.cipher, band: wifi.band,
      channel: wifi.channel, signal_dbm: wifi.signal_dbm,
      source: wifi.source || wifi.scan_source || wifi.capability || 'Operating-system Wi-Fi adapter',
      observed_at: wifi.observed_at || snapshot.observed_at,
    };
    const history = options.history || [];
    const findings = payload ? (payload.findings || []) : [];
    const checks = payload ? (payload.checks || []) : [];
    const recommendations = payload ? (payload.recommendations || []) : [];
    const actions = active ? (active.remediations || []) : [];
    const verifications = payload ? (payload.remediation_verification || []) : [];
    const riskCard = score?.status === 'scored'
      ? `<div class="audit-risk"><div class="eyebrow">OBSERVED RISK · ${esc(score.model_version || payload.model_version || 'model unknown')}</div><strong>${reported(score.value)}<small>/100</small></strong><span>${chip(score.band)}</span><p>${esc(score.note || 'Product-defined risk index based on persisted observations.')}</p></div>`
      : `<div class="audit-risk audit-risk-unknown"><div class="eyebrow">RISK SCORE</div><strong>Insufficient evidence</strong><p>${esc(score?.reason || 'Run an authorized audit and collect evidence from at least two core checks.')}</p></div>`;
    const checkRows = checks.length ? checks.map(check => `<article class="audit-check"><div class="split"><b>${reported(check.label || check.id)}</b>${chip(check.status)}</div><p>${reported(check.detail)}</p>${check.evidence ? `<details><summary>Evidence</summary><pre>${esc(JSON.stringify(check.evidence, null, 2))}</pre></details>` : ''}</article>`).join('') : '<div class="empty">No audit checks have been stored yet.</div>';
    const findingRows = findings.length ? findings.map(finding => {
      const contribution = (score?.contributions || []).find(row => row.check_id === finding.check_id);
      return `<article class="audit-finding"><div class="split"><div><div class="eyebrow">${reported(finding.category)} · ${reported(finding.confidence)} confidence</div><b>${reported(finding.title)}</b></div>${chip(finding.severity)}</div><p>${reported(finding.description)}</p><p><b>Impact:</b> ${reported(finding.impact)}</p><p class="muted">Risk contribution: ${contribution ? `${reported(contribution.contribution)} points${contribution.included_in_score === false ? ' · correlated group maximum already counted' : ''}` : 'Not scored because evidence is insufficient.'}</p><details><summary>Evidence and verification</summary><pre>${esc(JSON.stringify({source: finding.source, observed_at: finding.observed_at, evidence: finding.evidence, risk_factors: finding.risk_factors, verification: finding.verification}, null, 2))}</pre></details></article>`;
    }).join('') : '<div class="empty">No evidence-backed findings were recorded for this audit.</div>';
    const remediationRows = recommendations.length ? `<ol class="audit-remediations">${recommendations.slice().sort((a, b) => Number(a.priority || 99) - Number(b.priority || 99)).map(item => {
      const action = actions.find(row => row.finding_id === item.finding_id);
      const verified = verifications.find(row => row.finding_id === item.finding_id);
      const status = verified?.status || action?.status || item.status || 'open';
      const toggleApplied = action?.status !== 'applied';
      const tracking = item.finding_id
        ? `<button class="ghost" type="button" onclick="markWifiRemediationApplied('${esc(active.id)}','${esc(item.finding_id)}',${toggleApplied})">${toggleApplied ? 'Mark as applied' : 'Undo applied status'}</button><div class="muted">Applied is a user note only. A later audit must supply evidence before this is marked verified.</div>`
        : '<div class="muted">General guidance; no vulnerability is claimed by this recommendation.</div>';
      return `<li><b>${reported(item.title)}</b><p>${reported(item.action)}</p><div class="muted">Verify: ${reported(item.verification)} · Status: ${reported(status)}</div>${verified ? `<div class="audit-verification">New check: ${reported(verified.detail)} · ${reported(verified.verified_at)}</div>` : ''}${tracking}</li>`;
    }).join('')}</ol>` : '<div class="empty">No remediation actions are associated with this audit.</div>';
    const verificationPanel = verifications.length ? `<section class="panel audit-verification-panel"><div class="panel-head"><b>Rechecked previous remediation</b><span>${verifications.length} rechecked</span></div><div class="panel-body audit-check-list">${verifications.map(item => `<article class="audit-check"><div class="split"><b>${reported(item.title || item.check_id)}</b>${chip(item.status)}</div><p>${reported(item.detail)}</p><details><summary>New verification evidence</summary><pre>${esc(JSON.stringify(item.evidence || {}, null, 2))}</pre></details></article>`).join('')}</div></section>` : '';
    const limits = payload ? (payload.limitations || []) : [];
    const severityCounts = ['Critical', 'High', 'Medium', 'Low', 'Informational'].map(severity =>
      `${severity}: ${findings.filter(item => item.severity === severity).length}`).join(' · ');
    const historyRows = history.length ? history.map(item => {
      const entry = item.payload || {};
      const entryScore = entry.score || {};
      const entryNetwork = entry.network || {};
      const valid = item.integrity_valid === true;
      return `<button type="button" class="audit-history-item" ${valid ? `onclick="openWifiAudit('${esc(item.id)}')"` : 'disabled'}><span><b>${reported(item.id)}</b><small>${reported(item.created_at)} · ${reported(entryNetwork.ssid)}</small></span><span>${valid ? `${entryScore.status === 'scored' ? `${reported(entryScore.value)}/100 · ${reported(entryScore.band)}` : 'Insufficient evidence'}` : 'Integrity check failed'}</span></button>`;
    }).join('') : '<div class="empty">No Wi-Fi audits have been saved.</div>';
    const refreshing = snapshot.refreshing ? '<div class="muted">A background OS refresh is in progress; displayed context keeps its source timestamp.</div>' : '';
    const status = payload ? payload.status : (wifi.connected === true ? 'connected' : (wifi.state || 'not observed'));
    const authorizationChecked = options.authorized === true;
    const auditRunning = options.running === true;

    return `<div class="audit-page">
      <section class="audit-hero"><div><div class="eyebrow">READ-ONLY WIFI CONFIGURATION REVIEW</div><h2>Wi-Fi Security Audit</h2><p>Review the network attached to this computer using operating-system observations and one bounded gateway reachability check.</p><div class="live-meta">${chip(status)}<span>Source: ${reported(identity.source)}</span><span>Observed: ${reported(identity.observed_at)}</span></div>${refreshing}</div></section>
      <div class="grid g2 audit-top-grid"><section class="panel"><div class="panel-head"><b>Current network context</b><span class="live-chip">${reported(identity.connection_state)}</span></div><div class="panel-body audit-network-grid">${metric('SSID', identity.ssid || (identity.ssid_hidden ? 'SSID reported hidden' : null))}${metric('BSSID', identity.bssid)}${metric('Interface', identity.interface)}${metric('Gateway', identity.gateway)}${metric('Local IP / subnet', [identity.local_ip, identity.subnet].filter(Boolean).join(' / ') || null)}${metric('Band / channel', [identity.band ? `${identity.band} GHz` : null, identity.channel ? `ch ${identity.channel}` : null].filter(Boolean).join(' · ') || null)}${metric('Authentication / cipher', [identity.authentication, identity.cipher].filter(Boolean).join(' / ') || null)}${metric('Signal', identity.signal_dbm == null ? null : `${identity.signal_dbm} dBm`)}</div></section>
      <section class="panel"><div class="panel-head"><b>Run an authorized audit</b></div><div class="panel-body"><p class="muted">The audit reads connected network metadata and pings only the OS-reported gateway. It does not scan other hosts or change router settings.</p><label class="check audit-consent"><input type="checkbox" ${authorizationChecked ? 'checked' : ''} onchange="state.wifiAuditAuthorized=this.checked" ${auditRunning ? 'disabled' : ''}> I am authorized to assess this currently connected network.</label><button class="primary" type="button" onclick="runWifiAudit()" ${authorizationChecked && !auditRunning ? '' : 'disabled'}>${auditRunning ? 'Audit running…' : 'Run Wi-Fi Security Audit'}</button></div></section></div>
      <section class="panel audit-credential-panel"><div class="panel-head"><div><b>Saved Credential</b><div class="muted">Optional · current connected network only</div></div><span class="live-chip">OS protected</span></div><div class="panel-body"><p class="muted">Request the saved Wi-Fi password only when needed. macOS may ask Keychain to authorize access; Windows requires an elevated WiFiSentinel process. It is never stored in audit history or exported, and is never sent to AI.</p><div class="audit-credential-controls"><input id="wifi-current-credential" type="password" readonly autocomplete="off" spellcheck="false" placeholder="Not requested" aria-label="Saved Wi-Fi credential, masked"><button class="ghost" type="button" onclick="requestWifiCredential()">Request from operating system</button><button class="ghost" id="wifi-credential-reveal" type="button" disabled onclick="toggleWifiCredential()">Reveal</button><button class="ghost" id="wifi-credential-copy" type="button" disabled onclick="copyWifiCredential()">Copy</button><button class="ghost" id="wifi-credential-clear" type="button" disabled onclick="clearWifiCredential()">Clear</button></div><div id="wifi-credential-status" class="muted" role="status" aria-live="polite">Credential has not been requested.</div><div class="muted audit-credential-note">If access is denied or unsupported, inspect the current network in Keychain Access on macOS, or Windows Wi-Fi network properties. No other saved profile is queried.</div></div></section>
      ${payload ? `<div class="grid g2 audit-result-grid">${riskCard}<section class="panel"><div class="panel-head"><b>Coverage and model</b><span>${reported(coverage.checks_observed)} / ${reported(coverage.checks_total)} checks observed</span></div><div class="panel-body"><div class="audit-metric"><span>Core evidence</span><b>${reported(coverage.core_checks_observed)} / ${reported(coverage.core_checks_total)}</b></div><div class="audit-metric"><span>Model version</span><b>${reported(payload.model_version)}</b></div><div class="audit-severity">${esc(severityCounts)}</div><p class="muted">${esc(score.formula || '')}</p><details class="audit-model-details"><summary>Scoring input rationale</summary><ul>${Object.entries(score.factor_rationale || {}).map(([key, value]) => `<li><b>${esc(key.replaceAll('_', ' '))}:</b> ${esc(value)}</li>`).join('')}</ul><p class="muted">Product-defined bands: ${esc(JSON.stringify(score.risk_band_thresholds || {}))}. These thresholds are not an industry standard.</p></details><button class="primary" type="button" onclick="exportWifiAuditPdf('${esc(active.id)}')">Export PDF Report</button></div></section></div>
      <div class="grid g2 audit-sections"><section class="panel"><div class="panel-head"><b>Security checks</b><span>${checks.length} checks</span></div><div class="panel-body audit-check-list">${checkRows}</div></section><section class="panel"><div class="panel-head"><b>Findings</b><span>${findings.length} evidence-backed</span></div><div class="panel-body audit-check-list">${findingRows}</div></section></div>
      ${verificationPanel}
      <section class="panel audit-remediation-panel"><div class="panel-head"><b>Prioritized remediation</b></div><div class="panel-body">${remediationRows}</div></section>
      <section class="panel audit-limitations-panel"><div class="panel-head"><b>Coverage limits and manual verification</b></div><div class="panel-body">${limits.length ? `<ul>${limits.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p class="muted">No additional limitations were recorded.</p>'}<p class="muted">DNS configuration and router controls such as WPS, firmware, isolation, and administration access require OS support or owner-side verification. Saved credential access is optional, requires a separate OS-authorized request, and is not included in audit evidence.</p></div></section>`
      : `<section class="panel audit-empty"><div class="panel-head"><b>Audit result</b></div><div class="panel-body"><div class="empty">No audit is selected. Confirm authorization and run an audit to store a result from current OS evidence.</div></div></section>`}
      <section class="panel audit-other-workflows"><div class="panel-head"><b>Other authorized assessment workflows</b></div><div class="panel-body"><p class="muted">This page reviews the connected interface. Use the existing workflows for bounded LAN discovery, local tool observations, or offline PCAP evidence; those records remain separate from this audit.</p><div class="row-actions"><button class="ghost" onclick="go('assessments')">Authorized LAN / wireless assessments</button><button class="ghost" onclick="go('capture')">Offline PCAP Review</button><button class="ghost" onclick="go('tools')">Tool availability</button></div></div></section>
      <section class="panel audit-history"><div class="panel-head"><b>Wi-Fi audit history</b><span>${history.length} saved</span></div><div class="panel-body">${historyRows}</div></section>
    </div>`;
  }
  return { render, escapeHtml: esc };
});
