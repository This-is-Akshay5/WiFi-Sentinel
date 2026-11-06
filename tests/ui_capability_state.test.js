const test = require('node:test');
const assert = require('node:assert/strict');
const ui = require('../gui/js/capability_state.js');

test('native scan source is reported without a remote fallback state', () => {
  assert.equal(ui.scanSource({ capability: 'macos_native' }), 'macOS CoreWLAN');
  assert.equal(ui.scanStatus({ capability: 'macos_native', state: 'empty' }), 'LIVE EMPTY');
});

test('local permission denial remains visible and empty', () => {
  const wifi = { capability: 'macos_native', state: 'permission_required',
    nearby_aps: [], error: 'Allow Location Services' };
  assert.equal(ui.scanMessage({}, wifi), 'Allow Location Services');
  assert.equal(ui.scanSource(wifi), 'macOS CoreWLAN');
  assert.deepEqual(wifi.nearby_aps, []);
});

test('missing, empty, and permission states are not reported as live', () => {
  assert.equal(ui.scanStatus({ state: 'permission_required' }), 'PERMISSION REQUIRED');
  assert.equal(ui.scanStatus({ state: 'empty' }), 'LIVE EMPTY');
  assert.equal(ui.scanStatus({ state: 'ok' }), 'LIVE');
});

test('scan timeout, unavailable source, and unexpected error have distinct labels', () => {
  assert.equal(ui.scanStatus({ scan_attempt: { status: 'timeout' }, wifi: {} }), 'TIMEOUT');
  assert.equal(ui.scanStatus({ scan_attempt: { status: 'unavailable' }, wifi: {} }), 'UNAVAILABLE');
  assert.equal(ui.scanStatus({ scan_attempt: { status: 'error' }, wifi: {} }), 'ERROR');
});

test('native scan rows with withheld BSSID fields are shown as identifier-limited', () => {
  const snapshot = { wifi: { state: 'ok', freshness: 'live', identifier_access: 'limited',
    identifier_limitation: 'macOS Location Services may be withholding identifiers.' },
    scan_attempt: { status: 'success' } };
  assert.equal(ui.scanStatus(snapshot), 'IDENTIFIERS LIMITED');
  assert.match(ui.scanMessage(snapshot), /Location Services/);
});

test('initial scan does not show zero networks as a completed result', () => {
  assert.equal(ui.networkCountLabel({ refreshing: true, scan_attempt: { status: 'scanning' },
    wifi: { freshness: 'unavailable', nearby_aps: [] } }), 'Scanning for nearby networks…');
});

test('last successful networks stay explicitly cached after a failed refresh', () => {
  const snapshot = { refreshing: false, collection_error: 'permission required',
    scan_attempt: { status: 'permission_required', error: 'Allow Location Services' },
    wifi: { freshness: 'cached', nearby_aps: [{ ssid: 'Observed' }] } };
  assert.equal(ui.scanStatus(snapshot), 'CACHED · LAST GOOD');
  assert.equal(ui.networkCountLabel(snapshot), '1 network observed · cached');
  assert.equal(ui.scanMessage(snapshot), 'Allow Location Services');
});

test('a completed successful empty scan is distinct from scanning and failure', () => {
  const snapshot = { refreshing: false, scan_attempt: { status: 'empty' },
    wifi: { freshness: 'live', nearby_aps: [] } };
  assert.equal(ui.scanStatus(snapshot), 'LIVE EMPTY');
  assert.equal(ui.networkCountLabel(snapshot), '0 nearby networks observed');
});

test('local permission failure remains visible without substituting another data source', () => {
  const wifi = { state: 'permission_required', error: 'Allow Location Services', nearby_aps: [] };
  assert.equal(ui.scanStatus(wifi), 'PERMISSION REQUIRED');
  assert.equal(ui.scanMessage({}, wifi), 'Allow Location Services');
  assert.deepEqual(wifi.nearby_aps, []);
});

test('scan status includes the exact native OS failure reason alongside recovery guidance', () => {
  const wifi = { error: 'Allow Location Services', native_error: 'AuthorizationCreate() failed: -60008' };
  assert.match(ui.scanMessage({}, wifi), /Allow Location Services.*AuthorizationCreate\(\) failed: -60008/);
});

test('access point identity distinguishes BSSID-less observations that share SSID and channel', () => {
  const first = { ssid: 'Lab', channel: 36, band: 5, signal_dbm: -50, source: 'macOS CoreWLAN' };
  const second = { ssid: 'Lab', channel: 36, band: 5, signal_dbm: -72, source: 'independent test fixture' };
  assert.notEqual(ui.apIdentity(first), ui.apIdentity(second));
  assert.equal(ui.apIdentity({ bssid: 'AA:BB:CC:DD:EE:FF' }), 'bssid:aa:bb:cc:dd:ee:ff|source:');
});

test('an unreported SSID is distinct from an explicitly observed hidden SSID', () => {
  assert.equal(ui.ssidLabel({ ssid: null, ssid_observed: false, ssid_hidden: false }), 'SSID unavailable');
  assert.equal(ui.ssidLabel({ ssid: null, ssid_observed: true, ssid_hidden: true }), 'Hidden SSID');
});

test('network filtering searches identity and radio fields and sorts by supported columns', () => {
  const rows = [
    { ssid: 'Zulu', bssid: '02:00:00:00:00:02', band: 5, channel: 44, signal_dbm: -70, auth: 'WPA2' },
    { ssid: 'Alpha', bssid: '02:00:00:00:00:01', band: 2.4, channel: 6, signal_dbm: -42, auth: 'Open' },
  ];
  assert.deepEqual(ui.filterAndSortNetworks(rows, { query: '00:00:00:02', band: 'all', sort: 'bssid' }).map(x => x.index), [0]);
  assert.deepEqual(ui.filterAndSortNetworks(rows, { query: '', band: '2.4', sort: 'channel' }).map(x => x.index), [1]);
  assert.deepEqual(ui.filterAndSortNetworks(rows, { query: 'wpa2', band: 'all', sort: 'signal' }).map(x => x.index), [0]);
  assert.deepEqual(ui.filterAndSortNetworks(rows, { query: '', band: 'all', sort: 'name' }).map(x => x.index), [1, 0]);
});

test('refresh selection follows the same source observation without silently jumping rows', () => {
  const selected = { ssid: 'Lab', channel: 36, band: 5, source: 'CoreWLAN', signal_dbm: -60 };
  const refreshed = [
    { ssid: 'Lab', channel: 36, band: 5, source: 'CoreWLAN', signal_dbm: -62 },
    { ssid: 'Lab', channel: 36, band: 5, source: 'independent fixture', signal_dbm: -61 },
  ];
  assert.equal(ui.matchObservationIndex(selected, refreshed), 0);
  assert.equal(ui.matchObservationIndex(selected, [refreshed[1]]), -1);
});

test('passive deauthentication target picker keeps multiple real capture endpoints', () => {
  const frames = [
    { bssid: 'AA:BB:CC:DD:EE:FF', transmitter: 'AA:BB:CC:DD:EE:FF', receiver: '11:22:33:44:55:66' },
    { bssid: 'aa:bb:cc:dd:ee:ff', transmitter: 'AA:BB:CC:DD:EE:FF', receiver: '11:22:33:44:55:77' },
    { bssid: '00:00:00:00:00:01', transmitter: 'other', receiver: 'target' },
  ];
  assert.deepEqual(ui.deauthTargets(frames, 'aa:bb:cc:dd:ee:ff'), [
    'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66', '11:22:33:44:55:77',
  ]);
});

test('deauthentication UI explicitly excludes live mode and labels simulation', () => {
  assert.equal(ui.deauthModeSupported('passive'), true);
  assert.equal(ui.deauthModeSupported('simulation'), true);
  assert.equal(ui.deauthModeSupported('live'), false);
  assert.equal(ui.deauthModeLabel('simulation'), 'SIMULATION ONLY');
  assert.equal(ui.deauthModeLabel('live'), 'NOT SUPPORTED');
});
