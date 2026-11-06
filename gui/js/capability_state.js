(function (root) {
  const state = {
    apIdentity(ap) {
      const bssid = String(ap?.bssid || '').trim().toLowerCase();
      if (bssid) return `bssid:${bssid}|source:${String(ap?.source || '').toLowerCase()}`;
      const fields = ['ssid', 'ssid_observed', 'ssid_hidden', 'channel', 'frequency_ghz', 'band',
        'signal_dbm', 'signal_pct', 'auth', 'cipher', 'radio_type', 'interface', 'source',
        'observed_at', 'first_seen', 'last_seen', '_observation_index'];
      return 'unkeyed:' + JSON.stringify(fields.map(key => ap?.[key] ?? null));
    },
    ssidLabel(ap) {
      if (ap?.ssid) return String(ap.ssid);
      if (ap?.ssid_observed === true && ap?.ssid_hidden === true) return 'Hidden SSID';
      return 'SSID unavailable';
    },
    matchObservationIndex(previous, observations = []) {
      if (!previous) return -1;
      const sameSource = ap => !previous.source || !ap?.source || previous.source === ap.source;
      if (previous.bssid) return observations.findIndex(ap => sameSource(ap) &&
        String(ap?.bssid || '').toLowerCase() === String(previous.bssid).toLowerCase());
      const stable = ['ssid', 'ssid_observed', 'ssid_hidden', 'channel', 'frequency_ghz', 'band',
        'auth', 'cipher', 'radio_type', 'interface', 'source'];
      const candidates = observations.map((ap, index) => ({ ap, index })).filter(({ ap }) => sameSource(ap) &&
        stable.every(key => (ap?.[key] ?? null) === (previous?.[key] ?? null)));
      if (candidates.length === 1) return candidates[0].index;
      if (candidates.length < 2) return -1;
      const signalKey = previous.signal_dbm != null ? 'signal_dbm' : previous.signal_pct != null ? 'signal_pct' : null;
      if (!signalKey) return -1;
      const withSignal = candidates.filter(({ ap }) => ap?.[signalKey] != null);
      if (!withSignal.length) return -1;
      withSignal.sort((a, b) => Math.abs(Number(a.ap[signalKey]) - Number(previous[signalKey])) -
        Math.abs(Number(b.ap[signalKey]) - Number(previous[signalKey])));
      if (withSignal.length > 1 && Math.abs(Number(withSignal[0].ap[signalKey]) - Number(previous[signalKey])) ===
          Math.abs(Number(withSignal[1].ap[signalKey]) - Number(previous[signalKey]))) return -1;
      return withSignal[0].index;
    },
    scanSource(wifi) {
      if (wifi?.capability === 'macos_native') return 'macOS CoreWLAN';
      if (wifi?.capability === 'windows_native_wlan') return 'Windows Native WLAN API';
      if (wifi?.capability === 'windows_netsh') return 'Windows WLAN fallback';
      return 'Operating-system WLAN';
    },
    scanStatus(value, refreshing = false, stale = false) {
      const snapshot = value?.wifi ? value : { wifi: value, refreshing, collection_error: stale };
      const wifi = snapshot.wifi || {};
      const attempt = snapshot.scan_attempt || {};
      if (snapshot.refreshing || attempt.status === 'scanning') return 'SCANNING';
      if (wifi.freshness === 'cached') return 'CACHED · LAST GOOD';
      if (wifi.identifier_access === 'limited') return 'IDENTIFIERS LIMITED';
      if (attempt.status === 'permission_required' || wifi?.state === 'permission_required') return 'PERMISSION REQUIRED';
      if (attempt.status === 'timeout' || wifi?.state === 'timeout') return 'TIMEOUT';
      if (attempt.status === 'error' || wifi?.state === 'error') return 'ERROR';
      if (attempt.status === 'unavailable' ||
          ['no_wireless_interface', 'scan_unavailable', 'wlan_unavailable', 'unsupported_platform'].includes(wifi?.state)) return 'UNAVAILABLE';
      if (attempt.status === 'empty' || wifi?.scan_outcome === 'empty' || wifi?.state === 'empty') return 'LIVE EMPTY';
      if (attempt.status === 'success' || wifi?.state === 'ok') return 'LIVE';
      if (wifi?.state === 'collecting') return 'CHECKING';
      return 'NO OBSERVATIONS';
    },
    networkCountLabel(snapshot) {
      const wifi = snapshot?.wifi || {};
      const aps = Array.isArray(wifi.nearby_aps) ? wifi.nearby_aps : [];
      if (!aps.length && (snapshot?.refreshing || snapshot?.scan_attempt?.status === 'scanning') &&
          wifi.freshness === 'unavailable') return 'Scanning for nearby networks…';
      if (wifi.freshness === 'cached') return `${aps.length} ${aps.length === 1 ? 'network' : 'networks'} observed · cached`;
      if (snapshot?.scan_attempt?.status === 'empty' || wifi.scan_outcome === 'empty' || wifi.state === 'empty') {
        return '0 nearby networks observed';
      }
      if (!aps.length && ['error', 'permission_required', 'unavailable', 'timeout'].includes(snapshot?.scan_attempt?.status)) {
        return 'No current scan result';
      }
      if (!aps.length && (snapshot?.refreshing || snapshot?.scan_attempt?.status === 'scanning')) {
        return 'Scanning for nearby networks…';
      }
      return `${aps.length} nearby network${aps.length === 1 ? '' : 's'} observed`;
    },
    scanMessage(snapshot, wifi = snapshot?.wifi || {}) {
      const message = snapshot?.scan_attempt?.error || snapshot?.collection_error || wifi?.error || wifi?.local_scan_error || wifi?.identifier_limitation || '';
      const native = wifi?.native_error;
      return native && !String(message).includes(native) ? `${message}${message ? ' · ' : ''}Native reason: ${native}` : message;
    },
    filterAndSortNetworks(observations = [], options = {}) {
      const query = String(options.query || '').trim().toLowerCase();
      const band = String(options.band || 'all');
      const sort = options.sort || 'signal';
      const searchable = row => [row?.ssid, row?.bssid, row?.band, row?.frequency_ghz, row?.channel,
        row?.signal_dbm, row?.signal_pct, row?.auth, row?.cipher, row?.radio_type, row?.source,
        row?.interface, row?.country_code, row?.supported_rates_mbps, row?.capability_flags]
        .flatMap(value => Array.isArray(value) ? value : [value]).map(value => String(value ?? '').toLowerCase()).join(' ');
      const result = observations.map((a, index) => ({ a, index })).filter(({ a }) => {
        const effectiveBand = a?.band ?? a?.frequency_ghz;
        return (!query || searchable(a).includes(query)) && (band === 'all' || String(effectiveBand) === band);
      });
      const textValue = row => String(row ?? '').toLowerCase();
      const numberValue = row => row == null || row === '' ? Number.POSITIVE_INFINITY : Number(row);
      result.sort((left, right) => {
        const a = left.a || {}, b = right.a || {};
        if (sort === 'name' || sort === 'bssid' || sort === 'security') {
          const key = sort === 'name' ? 'ssid' : sort === 'security' ? 'auth' : 'bssid';
          return textValue(a[key]).localeCompare(textValue(b[key]));
        }
        if (sort === 'band') return numberValue(a.band ?? a.frequency_ghz) - numberValue(b.band ?? b.frequency_ghz);
        if (sort === 'channel') return numberValue(a.channel) - numberValue(b.channel);
        const leftSignal = a.signal_dbm ?? a.signal_pct;
        const rightSignal = b.signal_dbm ?? b.signal_pct;
        return numberValue(rightSignal) - numberValue(leftSignal);
      });
      return result;
    },
    deauthTargets(frames = [], bssid = '') {
      const key = String(bssid || '').toLowerCase();
      return [...new Set(frames.filter(row => !key || String(row?.bssid || '').toLowerCase() === key)
        .flatMap(row => [row?.transmitter, row?.receiver]).filter(value => typeof value === 'string' && value.trim())
        .map(value => value.trim()))];
    },
    deauthModeSupported(mode) { return mode === 'passive' || mode === 'simulation'; },
    deauthModeLabel(mode) { return mode === 'simulation' ? 'SIMULATION ONLY' : mode === 'passive' ? 'PASSIVE ANALYSIS' : 'NOT SUPPORTED'; },
  };
  root.WiFiSentinelCapabilityState = state;
  if (typeof module !== 'undefined' && module.exports) module.exports = state;
})(typeof window === 'undefined' ? globalThis : window);
