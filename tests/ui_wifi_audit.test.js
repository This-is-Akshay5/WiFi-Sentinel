const test = require('node:test');
const assert = require('node:assert/strict');
const { render } = require('../gui/js/wifi_audit.js');

test('audit page escapes OS text and labels unavailable fields without inventing values', () => {
  const html = render({
    snapshot: { wifi: { connected: true, ssid: '<script>bad</script>', bssid: null },
                network: { gateway: null }, observed_at: '2026-10-15T12:00:00Z' },
    history: [], authorized: false,
  });
  assert.match(html, /&lt;script&gt;bad&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>bad/);
  assert.match(html, /Not reported/);
  assert.match(html, /I am authorized/);
  assert.match(html, /never stored in audit history or exported/);
  assert.match(html, /disabled/);
});

test('insufficient evidence and unavailable checks are not rendered as a low score or pass', () => {
  const html = render({
    snapshot: {}, history: [], authorized: true,
    active: { id: 'WFA-1', integrity_valid: true, payload: {
      status: 'partial', score: { status: 'insufficient_evidence', value: null,
                                 reason: 'Two core checks have no evidence.' },
      coverage: { checks_observed: 0, checks_total: 7, core_checks_observed: 0, core_checks_total: 3 },
      checks: [{ id: 'pmf', label: 'PMF', status: 'unavailable', detail: 'No exact BSSID match.' }],
      findings: [{ id: 'FND-1', check_id: 'security_mode', severity: 'High', confidence: 'High',
                   title: 'Legacy mode', description: 'Observed legacy security.',
                   risk_factors: { exploitability: 0.8 } }],
      recommendations: [{ finding_id: 'FND-1', priority: 1, title: 'Update security',
                          action: 'Configure WPA2-AES.', verification: 'Run the audit again.', status: 'open' }],
      remediation_verification: [{ finding_id: 'FND-1', check_id: 'security_mode',
                                    title: 'Legacy mode', status: 'still_present', detail: 'Still observed.' }],
      limitations: ['DNS unavailable'], network: {},
    }, remediations: [{ finding_id: 'FND-1', status: 'applied' }] },
  });
  assert.match(html, /Insufficient evidence/);
  assert.doesNotMatch(html, />Low</);
  assert.match(html, /unavailable/);
  assert.match(html, /No exact BSSID match/);
  assert.match(html, /WFA-1/);
  assert.match(html, /Export PDF Report/);
  assert.match(html, /Undo applied status/);
  assert.match(html, /Applied is a user note only/);
  assert.match(html, /still_present/);
});

test('audit history remains separately selectable and escaped', () => {
  const html = render({ snapshot: {}, authorized: false, history: [
    { id: 'WFA-2', created_at: '2026-10-15T10:00:00Z', integrity_valid: true,
      payload: { score: { status: 'scored', value: 32, band: 'Moderate' }, network: { ssid: 'Home' } } },
    { id: '<bad>', created_at: '2026-10-14T10:00:00Z', integrity_valid: false,
      payload: { score: { status: 'scored', value: 95, band: 'Critical' }, network: {} } },
  ] });
  assert.match(html, /WFA-2/);
  assert.match(html, /&lt;bad&gt;/);
  assert.match(html, /Integrity check failed/);
});

test('running audit state disables duplicate submission', () => {
  const html = render({ snapshot: {}, history: [], authorized: true, running: true });
  assert.match(html, /Audit running/);
  assert.match(html, /disabled/);
});

test('saved credential stays masked until the explicit operating-system request', () => {
  const html = render({ snapshot: {}, history: [], authorized: false });
  assert.match(html, /Saved Credential/);
  assert.match(html, /Request from operating system/);
  assert.match(html, /type="password"/);
  assert.match(html, /Reveal/);
  assert.match(html, /Copy/);
  assert.match(html, /never stored in audit history or exported/);
});
