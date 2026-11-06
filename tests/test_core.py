import unittest,tempfile,sqlite3
from concurrent.futures import Future
from pathlib import Path
import sys;sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.dataset_engine import DatasetEngine
from core.store import Store
from core.wifi_engine import RealWiFiEngine
ROOT=Path(__file__).resolve().parents[1]
class Tests(unittest.TestCase):
    def test_dataset_integrity(self):
        s=DatasetEngine(ROOT/'data/wifi_association_disassociation.csv').summary(); self.assertEqual(s['records'],144720); self.assertEqual(s['labels']['attack'],111605); self.assertEqual(s['labels']['normal'],33115)
    def test_dataset_analytics_reuse_parsed_rows(self):
        engine=DatasetEngine(ROOT/'data/wifi_association_disassociation.csv')
        engine.summary()
        cached=engine._rows_cache
        engine.analyze()
        self.assertIs(engine._rows_cache,cached)
    def test_dataset_detection(self):
        d=DatasetEngine(ROOT/'data/wifi_association_disassociation.csv').detection(); self.assertGreater(d['count'],0)
    def test_store_no_seeded_assessment(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'x.db'); self.assertEqual(st.assessments(),[])
    def test_theme_setting_persists_across_store_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'settings.db';store=Store(path)
            store.set_setting('theme','light')
            store.close();reopened=Store(path)
            try:self.assertEqual(reopened.setting('theme',''),'light')
            finally:reopened.close()
    def test_hidden_ssid_evidence_survives_store_and_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'ssid.db';store=Store(path)
            assessment=store.create_assessment({'name':'Hidden network observation'})
            store.add_network(assessment['id'],{'ssid':None,'ssid_observed':True,'ssid_hidden':True,
                            'bssid':'11:22:33:44:55:66','observed_at':'2026-10-11T00:00:00Z'})
            store.close();reopened=Store(path)
            try:
                network=reopened.state(assessment['id'],include_all=True)['networks'][0]
                self.assertEqual(network['ssid_observed'],1)
                self.assertEqual(network['ssid_hidden'],1)
            finally:reopened.close()
    def test_device_discovery_history_survives_reopen_and_marks_interrupted_jobs(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'history.db';store=Store(path)
            job={'id':'scan-123','scope':'192.168.4.0/24','interface':'en0','status':'running',
                 'started_at':'2026-10-10T10:00:00Z','finished_at':None,'checked':8,'total':253,
                 'results':[{'ip':'192.168.4.1','source':'ICMP echo response','observed_at':'2026-10-10T10:00:01Z'}],
                 'limitations':['Non-response does not prove absence.']}
            store.save_device_discovery(job);store.close()
            reopened=Store(path)
            try:
                reopened.recover_interrupted_device_discoveries()
                saved=reopened.latest_device_discovery(1)[0]
                self.assertEqual(saved['status'],'interrupted')
                self.assertEqual(saved['results'],job['results'])
                self.assertEqual(saved['scope'],job['scope'])
            finally:reopened.close()
    def test_scope(self):
        from core.assessment_engine import AssessmentEngine
        class C: pass
        e=AssessmentEngine(C(),RealWiFiEngine(),DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        self.assertTrue(e._in_scope('192.168.1.10','192.168.1.0/24')); self.assertFalse(e._in_scope('10.0.0.10','192.168.1.0/24'))
    def test_unknown_wireless_security_is_not_reported_as_open(self):
        from core.assessment_engine import _is_open_or_legacy
        self.assertFalse(_is_open_or_legacy({'auth':None,'cipher':None}))
        self.assertFalse(_is_open_or_legacy({'auth':'WPA2-Personal','cipher':None}))
        self.assertTrue(_is_open_or_legacy({'auth':'Open','cipher':'None'}))
        self.assertTrue(_is_open_or_legacy({'auth':'WPA2-Personal','cipher':'TKIP'}))
if __name__=='__main__':unittest.main()

class WiFiParsingTests(unittest.TestCase):
    def test_windows_native_scan_parser_distinguishes_empty_from_missing_ssid(self):
        engine=RealWiFiEngine();engine.os_type='Windows'
        hidden=engine._parse_nearby('SSID 1 :\n    BSSID 1 : 11:22:33:44:55:66\n')
        absent=engine._parse_nearby('BSSID 1 : 11:22:33:44:55:67\n')
        self.assertTrue(hidden[0]['ssid_hidden'])
        self.assertTrue(hidden[0]['ssid_observed'])
        self.assertFalse(absent[0]['ssid_hidden'])
        self.assertFalse(absent[0]['ssid_observed'])

    def test_windows_native_frequency_and_rsn_security_parser(self):
        from core.windows_wlan import _channel, _security
        self.assertEqual(_channel(2412000),(1,2.4))
        self.assertEqual(_channel(5180000),(36,5.0))
        self.assertEqual(_channel(5955000),(1,6.0))
        # RSN 1.0, CCMP group/pairwise, one PSK AKM.
        rsn_body=bytes.fromhex('0100000fac040100000fac040100000fac02')
        auth,cipher=_security(bytes([48,len(rsn_body)])+rsn_body,True)
        self.assertEqual(auth,'WPA2 Personal')
        self.assertEqual(cipher,'CCMP')

    def test_windows_native_bss_entry_uses_bounded_os_fields(self):
        import ctypes
        from core.windows_wlan import DWORD, WLAN_BSS_ENTRY, _decode_entry
        rsn_body=bytes.fromhex('0100000fac040100000fac040100000fac02')
        ies=bytes([48,len(rsn_body)])+rsn_body
        total=ctypes.sizeof(DWORD)*2+ctypes.sizeof(WLAN_BSS_ENTRY)+len(ies)
        storage=ctypes.create_string_buffer(total)
        base=ctypes.addressof(storage)
        header=ctypes.cast(base,ctypes.POINTER(DWORD*2)).contents
        header[0],header[1]=total,1
        entry_address=base+ctypes.sizeof(DWORD)*2
        entry=ctypes.cast(entry_address,ctypes.POINTER(WLAN_BSS_ENTRY)).contents
        entry.dot11Ssid.uSSIDLength=0
        entry.dot11Bssid[:]=(0x11,0x22,0x33,0x44,0x55,0x66)
        entry.lRssi=-47;entry.uLinkQuality=91;entry.usCapabilityInformation=0x10
        entry.ulChCenterFrequency=5180000
        entry.usBeaconPeriod=100
        entry.uPhyId=7
        entry.dot11BssPhyType=7
        entry.wlanRateSet.uRateSetLength=2
        entry.wlanRateSet.usRateSet[:2]=(12,24)
        entry.ulIeOffset=ctypes.sizeof(WLAN_BSS_ENTRY);entry.ulIeSize=len(ies)
        ctypes.memmove(entry_address+entry.ulIeOffset,ies,len(ies))
        ap=_decode_entry(entry,entry_address,base,total,'Wi-Fi')
        self.assertEqual(ap['bssid'],'11:22:33:44:55:66')
        self.assertFalse(ap['ssid_hidden'])
        self.assertFalse(ap['ssid_observed'])
        self.assertEqual(ap['signal_dbm'],-47)
        self.assertEqual((ap['channel'],ap['band']),(36,5.0))
        self.assertEqual((ap['auth'],ap['cipher']),('WPA2 Personal','CCMP'))
        self.assertEqual(ap['beacon_interval_ms'],100)
        self.assertEqual(ap['supported_rates_mbps'],[6.0,12.0])
        self.assertEqual(ap['radio_type'],'802.11n')
        self.assertFalse(ap['ssid_observed'])

    def test_windows_hidden_ssid_requires_an_explicit_empty_ssid_information_element(self):
        import ctypes
        from core.windows_wlan import DWORD, WLAN_BSS_ENTRY, _decode_entry
        ies=bytes([0,0])
        total=ctypes.sizeof(DWORD)*2+ctypes.sizeof(WLAN_BSS_ENTRY)+len(ies)
        storage=ctypes.create_string_buffer(total);base=ctypes.addressof(storage)
        header=ctypes.cast(base,ctypes.POINTER(DWORD*2)).contents;header[0],header[1]=total,1
        addr=base+ctypes.sizeof(DWORD)*2;entry=ctypes.cast(addr,ctypes.POINTER(WLAN_BSS_ENTRY)).contents
        entry.dot11Bssid[:]=(0x11,0x22,0x33,0x44,0x55,0x67)
        entry.ulIeOffset=ctypes.sizeof(WLAN_BSS_ENTRY);entry.ulIeSize=len(ies)
        ctypes.memmove(addr+entry.ulIeOffset,ies,len(ies))
        ap=_decode_entry(entry,addr,base,total,'Wi-Fi')
        self.assertTrue(ap['ssid_observed'])
        self.assertTrue(ap['ssid_hidden'])

    def test_corewlan_prefers_unrestricted_ssid_scan_and_preserves_radio_metadata(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        class Channel:
            def channelNumber(self): return 36
            def channelBand(self): return 2
            def channelWidth(self): return 3
        class Network:
            def ssid(self): return 'Office'
            def ssidData(self): return b'Office'
            def bssid(self): return '02:11:22:33:44:55'
            def rssiValue(self): return -51
            def wlanChannel(self): return Channel()
            def strongestSupportedSecurity(self): return 4
            def beaconInterval(self): return 100
            def countryCode(self): return 'US'
            def noiseMeasurement(self): return -92
            def ibss(self): return False
            def informationElementData(self): return bytes([0,6])+b'Office'+bytes([48,2])+b'\x01\x00'
        class Interface:
            def scanForNetworksWithSSID_includeHidden_error_(self,ssid,include_hidden,error):
                assert ssid is None and include_hidden is True
                return ({Network()},None)
        class Client:
            def interfaceWithName_(self,name): return Interface()
        adapter=MacOSAdapter(RealWiFiEngine())
        with patch.object(MacOSAdapter,'_corewlan',return_value=(SimpleNamespace(),Client())):
            rows,error=adapter._corewlan_scan('en0')
        self.assertIsNone(error)
        self.assertEqual(rows[0]['ssid'],'Office')
        self.assertEqual(rows[0]['bssid'],'02:11:22:33:44:55')
        self.assertEqual(rows[0]['scan_method'],'CoreWLAN scanForNetworksWithSSID(includeHidden=True)')
        self.assertEqual(rows[0]['beacon_interval_ms'],100)
        self.assertEqual(rows[0]['country_code'],'US')
        self.assertEqual(rows[0]['noise_dbm'],-92)
        self.assertEqual(rows[0]['channel_width'],'80 MHz')
        self.assertTrue(any(x['name']=='SSID' and x['length']==6 for x in rows[0]['information_elements']))
        self.assertEqual(rows[0]['diagnostic_fields']['beaconInterval'],{'native':100,'normalized':100})
        self.assertEqual(rows[0]['diagnostic_fields']['informationElementData']['native'],rows[0]['information_elements'])

    def test_macos_ssid_parser_labels_only_explicit_empty_names_as_hidden(self):
        from core.platform_adapters import MacOSAdapter
        aps=MacOSAdapter._parse_scan('SSID BSSID RSSI CHANNEL HT CC SECURITY\n'
                                     ' 11:22:33:44:55:66 -64 6 Y Y WPA2(AES)')
        self.assertEqual(aps[0]['ssid'],None)
        self.assertTrue(aps[0]['ssid_hidden'])

    def test_macos_scan_parser_preserves_ssid_spaces_and_real_rssi(self):
        from core.platform_adapters import MacOSAdapter
        aps=MacOSAdapter._parse_scan('SSID BSSID RSSI CHANNEL HT CC SECURITY\nGuest Office 11:22:33:44:55:66 -48 36,+1 Y Y WPA2(PSK/AES/AES)')
        self.assertEqual(len(aps),1)
        self.assertEqual(aps[0]['ssid'],'Guest Office')
        self.assertEqual(aps[0]['signal_dbm'],-48)
        self.assertEqual(aps[0]['channel'],36)
        self.assertIsNone(aps[0]['band'])
        self.assertIsNone(aps[0]['client_count'])

    def test_macos_discovery_selects_the_associated_wifi_interface(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine(); e.os_type='Darwin'; a=MacOSAdapter(e)
        a.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'},
                              {'name':'en5','description':'USB Wi-Fi','state':'available'}],None)
        a._airport=lambda:'/usr/sbin/airport'
        def run(cmd,timeout=8):
            if cmd==['networksetup','-getairportnetwork','en0']:
                return 0,'You are not associated with an AirPort network.',''
            if cmd==['networksetup','-getairportnetwork','en5']:
                return 0,'Current Wi-Fi Network: AuthorizedNet',''
            if cmd[-1:] == ['-I']:
                return 0,'state: running\nSSID: AuthorizedNet\nBSSID: 11:22:33:44:55:66\nagrCtlRSSI: -52\nchannel: 36',''
            if cmd[-1:] == ['-s']:
                return 0,'SSID BSSID RSSI CHANNEL HT CC SECURITY\nAuthorizedNet 11:22:33:44:55:66 -52 36,+1 Y Y WPA2(AES)',''
            return -2,'','missing'
        e._run=run
        with patch.object(MacOSAdapter,'_corewlan_connection',return_value={'signal_dbm':-52}), \
             patch.object(MacOSAdapter,'_corewlan_scan',return_value=([{'ssid':'AuthorizedNet','bssid':'11:22:33:44:55:66'}],None)):
            info=a.wifi_info()
        self.assertEqual(info['interface'],'en5')
        self.assertTrue(info['connected'])
        self.assertEqual(info['ssid'],'AuthorizedNet')
        self.assertEqual(info['signal_dbm'],-52)
        self.assertEqual(info['nearby_aps'][0]['interface'],'en5')
        self.assertEqual(info['nearby_aps'][0]['source'],'CoreWLAN')
        self.assertTrue(info['nearby_aps'][0]['observed_at'])

    def test_nonempty_corewlan_scan_is_classified_as_success(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        engine=RealWiFiEngine();engine.os_type='Darwin';adapter=MacOSAdapter(engine)
        adapter.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'}],None)
        adapter._airport=lambda:None
        engine._run=lambda cmd,timeout=8:(0,'You are not associated with an AirPort network.','')
        observed=[{'ssid':'Office','bssid':'02:11:22:33:44:55','source':'macOS CoreWLAN'}]
        with patch.object(MacOSAdapter,'_corewlan_scan',return_value=(observed,None)):
            info=adapter.wifi_info()
        self.assertEqual(info['nearby_aps'],observed)
        self.assertEqual(info['scan_outcome'],'success')

    def test_macos_missing_native_identifiers_are_reported_without_substitution(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        engine=RealWiFiEngine();engine.os_type='Darwin';adapter=MacOSAdapter(engine)
        adapter.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'}],None)
        adapter._airport=lambda:None
        engine._run=lambda cmd,timeout=8:(0,'Current Wi-Fi Network: CurrentNet','')
        rows=[{'ssid':None,'bssid':None,'ssid_observed':False,'source':'macOS CoreWLAN',
               'channel':36,'signal_dbm':-52}]
        with patch.object(MacOSAdapter,'_corewlan_scan',return_value=(rows,None)):
            info=adapter.wifi_info()
        self.assertEqual(info['scan_outcome'],'success')
        self.assertEqual(info['identifier_access'],'limited')
        self.assertIsNone(info['nearby_aps'][0]['bssid'])
        self.assertIn('Location Services',info['identifier_limitation'])

    def test_macos_permission_failure_is_reported_as_permission_required(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine();e.os_type='Darwin';a=MacOSAdapter(e)
        a.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'}],None)
        a._airport=lambda:None
        e._run=lambda cmd,timeout=8:(-1,'','AuthorizationCreate() failed: -60008')
        with patch.object(MacOSAdapter,'_corewlan_scan',return_value=(None,'AuthorizationCreate() failed: -60008')):
            info=a.wifi_info()
        self.assertEqual(info['state'],'permission_required')
        self.assertIn('permission',info['error'].lower())
        self.assertIn('AuthorizationCreate',info['native_error'])

    def test_macos_interface_enumeration_permission_error_has_actionable_recovery(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine();e.os_type='Darwin';a=MacOSAdapter(e)
        e._run=lambda cmd,timeout=8:(0,'AuthorizationCreate() failed: -60008','')
        with patch.object(MacOSAdapter,'_corewlan_records',return_value=(None,None)):
            interfaces,error=a.interfaces()
        self.assertEqual(interfaces,[])
        self.assertIn('run_simulator.command',error)
        self.assertIn('Location Services',error)

    def test_macos_interface_permission_denial_is_not_misreported_as_no_adapter(self):
        from core.platform_adapters import MacOSAdapter
        engine=RealWiFiEngine();engine.os_type='Darwin';adapter=MacOSAdapter(engine)
        adapter.interfaces=lambda:([],"macOS denied system Wi-Fi interface enumeration (AuthorizationCreate/permission error).")
        info=adapter.wifi_info()
        self.assertEqual(info['state'],'permission_required')
        self.assertIn('permission',info['error'].lower())

    def test_corewlan_scan_normalizes_real_network_fields(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        class Channel:
            def channelNumber(self): return 36
            def channelBand(self): return 2
        class Network:
            def ssid(self): return 'Office'
            def bssid(self): return 'aa:bb:cc:dd:ee:ff'
            def rssiValue(self): return -51
            def wlanChannel(self): return Channel()
            def strongestSupportedSecurity(self): return 4
        class HiddenNetwork:
            def ssid(self): return None
            def bssid(self): return None
            def rssiValue(self): return -77
            def wlanChannel(self): return Channel()
            def strongestSupportedSecurity(self): return 4
        class Interface:
            def scanForNetworksWithName_error_(self,name,error): return ({Network(),HiddenNetwork()},None)
            def ssid(self): return 'Office'
            def bssid(self): return 'aa:bb:cc:dd:ee:ff'
            def rssiValue(self): return -51
            def wlanChannel(self): return Channel()
            def security(self): return 4
        class Client:
            def interfaceNames(self): return ['en0']
            def interfaceWithName_(self,name): return Interface()
        adapter=MacOSAdapter(RealWiFiEngine())
        with patch.object(MacOSAdapter,'_corewlan',return_value=(SimpleNamespace(),Client())):
            aps,error=adapter._corewlan_scan('en0')
            connection=adapter._corewlan_connection('en0')
        self.assertIsNone(error)
        visible=next(ap for ap in aps if ap['bssid'])
        self.assertEqual(visible['bssid'],'AA:BB:CC:DD:EE:FF')
        self.assertEqual(visible['signal_dbm'],-51)
        self.assertEqual(visible['band'],5.0)
        self.assertIsNone(visible['frequency_ghz'])
        self.assertEqual(visible['auth'],'WPA2 Personal')
        self.assertEqual(visible['diagnostic_fields']['ssid'],{'native':'Office','normalized':'Office'})
        self.assertEqual(visible['diagnostic_fields']['bssid'],{'native':'aa:bb:cc:dd:ee:ff','normalized':'AA:BB:CC:DD:EE:FF'})
        hidden=next(ap for ap in aps if ap['signal_dbm']==-77)
        self.assertIsNone(hidden['ssid'])
        self.assertIsNone(hidden['bssid'])
        self.assertEqual(hidden['channel'],36)
        self.assertFalse(hidden['ssid_observed'])
        self.assertFalse(hidden['ssid_hidden'])
        self.assertTrue(connection['connected'])
        self.assertIsNone(connection['frequency_ghz'])

    def test_corewlan_ssid_data_recovers_valid_utf8_when_string_accessor_is_nil(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        class Channel:
            def channelNumber(self): return 6
            def channelBand(self): return 1
        class Network:
            def ssid(self): return None
            def ssidData(self): return b"Cafe Guest"
            def bssid(self): return "02:11:22:33:44:55"
            def rssiValue(self): return -53
            def wlanChannel(self): return Channel()
            def strongestSupportedSecurity(self): return 4
        class Interface:
            def scanForNetworksWithName_error_(self, name, error): return ({Network()}, None)
        class Client:
            def interfaceWithName_(self, name): return Interface()
        adapter=MacOSAdapter(RealWiFiEngine())
        with patch.object(MacOSAdapter,"_corewlan",return_value=(SimpleNamespace(),Client())):
            rows,error=adapter._corewlan_scan("en0")
        self.assertIsNone(error)
        self.assertEqual(rows[0]["ssid"],"Cafe Guest")
        self.assertTrue(rows[0]["ssid_observed"])
        self.assertFalse(rows[0]["ssid_hidden"])
        self.assertIsNone(rows[0]["diagnostic_fields"]["ssid"]["native"])
        self.assertEqual(rows[0]["diagnostic_fields"]["ssidData"]["native"],"43616665204775657374")

    def test_empty_corewlan_scan_uses_available_system_scan_fallback(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine();e.os_type='Darwin';a=MacOSAdapter(e)
        a.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'}],None)
        a._airport=lambda:'/system/airport'
        def run(cmd,timeout=8):
            if cmd==['networksetup','-getairportnetwork','en0']:
                return 0,'You are not associated with an AirPort network.',''
            if cmd[-1:]==['-I']:
                return -2,'','unavailable'
            if cmd[-1:]==['-s']:
                return 0,'SSID BSSID RSSI CHANNEL HT CC SECURITY\nLab Guest 11:22:33:44:55:66 -48 36,+1 Y Y WPA2(AES)',''
            return -2,'','missing'
        e._run=run
        with patch.object(MacOSAdapter,'_corewlan_scan',return_value=([],None)):
            info=a.wifi_info()
        self.assertEqual(info['state'],'ok')
        self.assertEqual(info['nearby_aps'][0]['ssid'],'Lab Guest')

    def test_successful_empty_corewlan_scan_stays_an_empty_observation_without_fallback(self):
        from unittest.mock import patch
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine();e.os_type='Darwin';a=MacOSAdapter(e)
        a.interfaces=lambda:([{'name':'en0','description':'Wi-Fi','state':'available'}],None)
        a._airport=lambda:None
        e._run=lambda cmd,timeout=8:(0,'You are not associated with an AirPort network.','')
        with patch.object(MacOSAdapter,'_corewlan_scan',return_value=([],None)):
            info=a.wifi_info()
        self.assertEqual(info['state'],'disconnected')
        self.assertEqual(info['nearby_aps'],[])
        self.assertIsNone(info['error'])

    def test_macos_network_context_and_neighbors_use_system_observations(self):
        from core.platform_adapters import MacOSAdapter
        e=RealWiFiEngine(); e.os_type='Darwin'; a=MacOSAdapter(e)
        def run(cmd,timeout=8):
            if cmd[:3]==['route','-n','get']:
                return 0,'gateway: 192.168.1.1\ninterface: en0\n',''
            if cmd[:2]==['ifconfig','en0']:
                return 0,'inet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n',''
            if cmd==['arp','-an']:
                return 0,'? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0\n',''
            return -2,'','missing'
        e._run=run
        context=a.network_context('en0')
        neighbors,error=a.neighbors()
        self.assertEqual(context['network'],'192.168.1.0/24')
        self.assertEqual(context['gateway'],'192.168.1.1')
        self.assertEqual(len(neighbors),1)
        self.assertEqual(neighbors[0]['mac'],'AA:BB:CC:DD:EE:FF')
        self.assertIsNone(error)

    def test_windows_nearby_parser_keeps_real_fields(self):
        from core.wifi_engine import RealWiFiEngine
        e=RealWiFiEngine()
        sample='''Interface name : Wi-Fi\n\nSSID 1 : TestNet\n    Network type : Infrastructure\n    Authentication : WPA2-Personal\n    Cipher : CCMP\n    BSSID 1 : 11:22:33:44:55:66\n         Signal : 92%\n         Radio type : 802.11ac\n         Channel : 36\n'''
        e.os_type='Windows'
        e._run=lambda *a,**k:(0,sample,'')
        aps=e.nearby_aps()
        self.assertEqual(len(aps),1)
        self.assertEqual(aps[0]['ssid'],'TestNet')
        self.assertEqual(aps[0]['bssid'],'11:22:33:44:55:66')
        self.assertEqual(aps[0]['signal_pct'],92)
        self.assertEqual(aps[0]['channel'],36)
        self.assertIsNone(aps[0]['band'])
        self.assertEqual(aps[0]['auth'],'WPA2-Personal')
        self.assertIsNone(aps[0]['client_count'])
        self.assertEqual(aps[0]['client_count_note'],'Not exposed by the OS WLAN scan')

    def test_windows_netsh_channel_alone_does_not_claim_frequency_or_band(self):
        engine=RealWiFiEngine();engine.os_type='Windows'
        ap=engine._parse_nearby('SSID 1 : TestNet\n  BSSID 1 : 11:22:33:44:55:66\n  Channel : 11\n')[0]
        self.assertEqual(ap['channel'],11)
        self.assertIsNone(ap['frequency_ghz'])
        self.assertIsNone(ap['band'])

    def test_macos_airport_channel_alone_does_not_claim_frequency_or_ambiguous_band(self):
        from core.platform_adapters import MacOSAdapter
        ap=MacOSAdapter._parse_scan('SSID BSSID RSSI CHANNEL HT CC SECURITY\nTestNet 11:22:33:44:55:66 -55 11 Y Y WPA2(AES)')[0]
        self.assertEqual(ap['channel'],11)
        self.assertIsNone(ap['frequency_ghz'])
        self.assertIsNone(ap['band'])

    def test_access_point_first_and_last_seen_follow_real_scan_timestamps(self):
        from core.wifi_engine import RealWiFiEngine
        engine=RealWiFiEngine()
        try:
            first={'wifi':{'observed_at':'2026-10-10T10:00:00Z','nearby_aps':[{'ssid':'Lab','bssid':'AA:BB:CC:DD:EE:FF','observed_at':'2026-10-10T10:00:00Z'}]}}
            later={'wifi':{'observed_at':'2026-10-10T10:01:00Z','nearby_aps':[{'ssid':'Lab','bssid':'AA:BB:CC:DD:EE:FF','observed_at':'2026-10-10T10:01:00Z'}]}}
            engine._track_ap_seen(first);engine._track_ap_seen(later)
            self.assertEqual(later['wifi']['nearby_aps'][0]['first_seen'],'2026-10-10T10:00:00Z')
            self.assertEqual(later['wifi']['nearby_aps'][0]['last_seen'],'2026-10-10T10:01:00Z')
        finally:engine.stop()

    def test_first_seen_history_does_not_merge_different_scan_sources(self):
        from core.wifi_engine import RealWiFiEngine
        engine=RealWiFiEngine()
        try:
            snapshot={'wifi':{'observed_at':'2026-10-10T10:00:00Z','nearby_aps':[
                {'bssid':'AA:BB:CC:DD:EE:FF','source':'macOS CoreWLAN','observed_at':'2026-10-10T10:00:00Z'},
                {'bssid':'AA:BB:CC:DD:EE:FF','source':'historical external scan','observed_at':'2026-10-10T10:00:00Z'}]}}
            engine._track_ap_seen(snapshot)
            self.assertEqual(len(engine._ap_first_seen),2)
        finally:engine.stop()

    def test_windows_network_context_parses_english_and_german_ipconfig(self):
        e=RealWiFiEngine();e.os_type='Windows'
        for output in (
            'Wireless LAN adapter Wi-Fi:\n   IPv4 Address. . . . . . . . . . . : 192.168.50.20\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 192.168.50.1\n',
            'Drahtlos-LAN-Adapter Wi-Fi:\n   IPv4-Adresse . . . . . . . . . . : 192.168.50.20\n   Subnetzmaske . . . . . . . . . . . : 255.255.255.0\n   Standardgateway . . . . . . . . . : 192.168.50.1\n',
        ):
            e._run=lambda *args,output=output,**kwargs:(0,output,'')
            context=e._network_context_raw('Wi-Fi')
            self.assertEqual(context['local_ip'],'192.168.50.20')
            self.assertEqual(context['subnet_mask'],'255.255.255.0')
            self.assertEqual(context['gateway'],'192.168.50.1')
            self.assertEqual(context['network'],'192.168.50.0/24')

    def test_multiple_interfaces_select_the_connected_adapter(self):
        e=RealWiFiEngine()
        e.os_type='Windows'
        e._run=lambda *a,**k:(0,'''Name                   : Wi-Fi 2
State                  : disconnected
\nName                   : Wi-Fi
State                  : connected
SSID                   : Office
BSSID                  : AA:BB:CC:DD:EE:FF
Channel                : 44
''','')
        info=e.wifi_info()
        self.assertEqual(len(info['interfaces']),2)
        self.assertEqual(info['interface'],'Wi-Fi')
        self.assertEqual(info['ssid'],'Office')
        self.assertEqual(info['channel'],44)

    def test_windows_background_snapshot_finishes_without_nested_pool_deadlock(self):
        import json
        e=RealWiFiEngine(); e.os_type='Windows'
        interface='''Name : Wi-Fi\nState : connected\nSSID : Office\nBSSID : AA:BB:CC:DD:EE:FF\nChannel : 6\nSignal : 80%\n'''
        scan='''SSID 1 : Office\n    Authentication : WPA2-Personal\n    Cipher : CCMP\n    BSSID 1 : AA:BB:CC:DD:EE:FF\n         Signal : 80%\n         Channel : 6\n'''
        def run(cmd,timeout=8):
            if cmd[:4]==['netsh','wlan','show','interfaces']: return 0,interface,''
            if cmd[:4]==['netsh','wlan','show','networks']: return 0,scan,''
            if cmd[0]=='powershell': return 0,json.dumps([]),''
            return 0,'',''
        e._run=run
        try:
            snap=e._executor.submit(e._collect_live_snapshot).result(timeout=3)
            self.assertTrue(snap['ready'])
            self.assertTrue(snap['wifi']['connected'])
            self.assertEqual(len(snap['wifi']['nearby_aps']),1)
        finally:
            e.stop()

    def test_live_snapshot_never_fakes_neighbor_ap_client_counts(self):
        from core.wifi_engine import RealWiFiEngine
        e=RealWiFiEngine()
        e.os_type='Other'
        snap=e.live_snapshot()
        self.assertFalse(snap['capabilities']['nearby_ap_client_counts'])

    def test_failed_refresh_preserves_last_successful_snapshot(self):
        import time
        e=RealWiFiEngine()
        e._cache={'ready':True,'wifi':{'state':'ok'},'devices':[],'observed_at':'previous'}
        e._cache_at=time.monotonic()-20
        failed=Future(); failed.set_exception(RuntimeError('collector failed'))
        e._generation=1;e._future_generation=1
        e._scan_attempt={'id':1,'status':'scanning','started_at':'previous','finished_at':None,
                         'successful_at':'previous','source':None,'error':None}
        e._future=failed
        snap=e.poll_refresh()
        self.assertEqual(snap['observed_at'],'previous')
        self.assertEqual(snap['wifi']['state'],'ok')
        self.assertEqual(snap['collection_error'],'collector failed')
        self.assertFalse(snap['refreshing'])
        self.assertIsNone(e._future)


class PersistenceAndScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name)/'scope.db')
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_authorization_updates_are_persisted(self):
        assessment=self.store.create_assessment({'name':'Authorization','authorization':False})
        updated=self.store.set_authorization(assessment['id'],True,'Written approval','Operator')
        self.assertEqual(updated['authorization'],1)
        self.assertEqual(updated['authorized_by'],'Operator')
        self.assertIsNotNone(updated['authorized_at'])

    def test_migration_adds_missing_execution_test_id_without_losing_existing_rows(self):
        assessment=self.store.create_assessment({'name':'Legacy schema'})
        original=self.store.start_execution(assessment['id'],'Old operation')
        path=self.store.path
        self.store.close()
        conn=sqlite3.connect(path)
        conn.execute('ALTER TABLE executions RENAME TO executions_with_test_id')
        conn.execute('CREATE TABLE executions(id TEXT PRIMARY KEY,assessment_id TEXT NOT NULL REFERENCES assessments(id),'
                     'test_type TEXT NOT NULL,status TEXT NOT NULL,stage TEXT NOT NULL,progress INTEGER NOT NULL,'
                     'started_at TEXT,completed_at TEXT,error TEXT,started_by TEXT)')
        conn.execute('INSERT INTO executions(id,assessment_id,test_type,status,stage,progress,started_at,completed_at,error,started_by) '
                     'SELECT id,assessment_id,test_type,status,stage,progress,started_at,completed_at,error,started_by FROM executions_with_test_id')
        conn.execute('DROP TABLE executions_with_test_id')
        conn.execute('PRAGMA user_version=8')
        conn.commit();conn.close()
        migrated=Store(path)
        try:
            columns={row['name'] for row in migrated.db.execute('PRAGMA table_info(executions)')}
            self.assertIn('test_id',columns)
            self.assertEqual(len(migrated.executions(assessment['id'])),1)
            new_id=migrated.start_execution(assessment['id'],'New operation','wifi_discovery')
            self.assertEqual(migrated.db.execute('SELECT test_id FROM executions WHERE id=?',(new_id,)).fetchone()['test_id'],'wifi_discovery')
            self.assertEqual(migrated.executions(assessment['id'])[0]['id'],new_id)
        finally:
            migrated.close()

    def test_assessment_registry_includes_findings_and_last_execution(self):
        assessment=self.store.create_assessment({'name':'Registry'})
        execution=self.store.start_execution(assessment['id'],'Test','catalog_test')
        evidence=self.store.add_evidence(assessment['id'],execution,'observation','test',{'seen':True})
        self.store.add_finding(assessment['id'],execution,'Observed issue','High','Description','Impact',
                               'Test','Observed from evidence','Remediate',evidence_id=evidence)
        row=self.store.assessment_registry()[0]
        self.assertEqual(row['findings_count'],1)
        self.assertEqual(row['high_count'],1)
        self.assertEqual(row['last_execution_at'],row['updated_at'])

    def test_evidence_lists_have_bounded_preview_and_full_detail(self):
        assessment=self.store.create_assessment({'name':'Evidence'})
        evidence_id=self.store.add_evidence(assessment['id'],None,'test','unit test','x'*2500)
        summary=self.store.evidence(assessment['id'])[0]
        self.assertEqual(len(summary['content_preview']),2000)
        self.assertEqual(summary['content_length'],2500)
        self.assertEqual(len(self.store.evidence_item(assessment['id'],evidence_id)['content']),2500)

    def test_offline_capture_evidence_is_not_counted_as_live_telemetry(self):
        from core.posture import calculate
        assessment=self.store.create_assessment({'name':'Capture-only review','authorization':True})
        execution=self.store.start_execution(assessment['id'],'Offline capture','offline_capture')
        self.store.add_evidence(assessment['id'],execution,'capture_analysis','PCAP review',{'eapol_frames':4},
                                {'data_class':'capture'},data_class='capture')
        posture=calculate(self.store.state(assessment['id']))
        self.assertEqual(posture['computed_from']['evidence_capture'],1)
        self.assertEqual(posture['computed_from']['evidence_live'],0)
        self.assertTrue(any('offline capture evidence' in x for x in posture['evidence_gaps']))

    def test_dataset_ai_history_is_separate_from_assessment_history(self):
        assessment=self.store.create_assessment({'name':'Selected'})
        self.store.save_ai_analysis(None,'dataset','test','{"source":"research"}')
        self.store.save_ai_analysis(assessment['id'],'assessment','test','{"source":"assessment"}')
        self.assertEqual([x['kind'] for x in self.store.ai_analyses(assessment['id'])],['assessment'])
        self.assertEqual([x['kind'] for x in self.store.ai_analyses(kind='dataset')],['dataset'])

    def test_assessment_wireless_evidence_is_filtered_to_declared_scope(self):
        from core.assessment_engine import AssessmentEngine
        class W:
            os_type='Darwin'
            def interfaces(self): return [{'name':'en0','state':'available'}]
            def wifi_info(self): return {'state':'ok','observed_at':'now','nearby_aps':[
                {'ssid':'Office','bssid':'AA:AA:AA:AA:AA:01','channel':1},
                {'ssid':'Guest','bssid':'BB:BB:BB:BB:BB:02','channel':6}]}
        assessment=self.store.create_assessment({'name':'Wi-Fi scope','authorization':True,'wireless_scope':'Office'})
        engine=AssessmentEngine(self.store,W(),DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        result=engine.run_test(assessment['id'],'wifi_discovery')
        self.assertEqual(result['status'],'completed')
        self.assertEqual([network['ssid'] for network in self.store.networks(assessment['id'])],['Office'])
        evidence=self.store.evidence_item(assessment['id'],self.store.evidence(assessment['id'])[0]['id'])['content']
        self.assertNotIn('Guest',evidence)

    def test_network_inventory_is_filtered_to_declared_cidr(self):
        from core.assessment_engine import AssessmentEngine
        class W:
            os_type='Darwin'
            def arp_devices(self): return [
                {'ip':'192.168.5.10','mac':'AA:AA:AA:AA:AA:10'},
                {'ip':'192.168.6.20','mac':'BB:BB:BB:BB:BB:20'}]
            def resolve_names(self,devices): return devices
        assessment=self.store.create_assessment({'name':'Network scope','authorization':True,'network_scope':'192.168.5.0/24'})
        engine=AssessmentEngine(self.store,W(),DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        result=engine.run_test(assessment['id'],'device_discovery')
        self.assertEqual(result['status'],'completed')
        self.assertEqual([device['ip'] for device in self.store.devices(assessment['id'])],['192.168.5.10'])

    def test_network_probe_outside_scope_is_blocked_before_connecting(self):
        from core.assessment_engine import AssessmentEngine
        class W:
            os_type='Darwin'
            def gateway(self): return None
            def tcp_ports(self,*args): raise AssertionError('out-of-scope connection attempt')
        assessment=self.store.create_assessment({'name':'Port scope','authorization':True,'network_scope':'192.168.5.0/24'})
        engine=AssessmentEngine(self.store,W(),DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        result=engine.run_test(assessment['id'],'port_assessment',{'host':'203.0.113.9','ports':[443]})
        self.assertEqual(result['status'],'blocked')


    def test_active_network_test_requires_permitted_scope_and_respects_exclusions(self):
        from datetime import datetime, timedelta, timezone
        from core.assessment_engine import AssessmentEngine

        class W:
            os_type = 'Darwin'
            def gateway(self): return None
            def tcp_ports(self, host, ports): return [{'port': port, 'state': 'closed'} for port in ports]

        assessment = self.store.create_assessment({'name': 'Engagement gate', 'authorization': True,
                                                    'network_scope': '192.168.5.0/24'})
        engine = AssessmentEngine(self.store, W(), DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        blocked = engine.run_test(assessment['id'], 'port_assessment', {'host': '192.168.5.10', 'ports': [443]})
        self.assertEqual(blocked['status'], 'blocked')
        start = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        end = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        base_policy = {'active': True, 'testing_start': start, 'testing_end': end,
                       'permitted_activities': ['port_assessment'], 'excluded_hosts': [],
                       'excluded_ip_ranges': [], 'testing_windows': []}
        self.store.set_scope_policy(assessment['id'], {**base_policy, 'excluded_hosts': ['192.168.5.10']})
        excluded = engine.run_test(assessment['id'], 'port_assessment', {'host': '192.168.5.10', 'ports': [443]})
        self.assertEqual(excluded['status'], 'blocked')
        self.store.set_scope_policy(assessment['id'], base_policy)
        result = engine.run_test(assessment['id'], 'port_assessment', {'host': '192.168.5.10', 'ports': [443]})
        self.assertEqual(result['status'], 'completed')

    def test_profile_with_missing_security_fields_is_only_informational(self):
        from core.assessment_engine import AssessmentEngine
        class W: os_type='Darwin'
        assessment=self.store.create_assessment({'name':'Unknown security'})
        evidence=self.store.add_evidence(assessment['id'],None,'wireless','test',{'auth':None,'cipher':None})
        engine=AssessmentEngine(self.store,W(),DatasetEngine(ROOT/'data/wifi_association_disassociation.csv'))
        engine._profile_findings(assessment['id'],None,{'connected':True,'ssid':'Office','auth':None,'cipher':None},evidence)
        self.assertEqual(self.store.findings(assessment['id'])[0]['severity'],'Informational')



class DeviceDiscoveryTests(unittest.TestCase):
    def make_engine(self,network='192.168.50.8/30',local_ip='192.168.50.9'):
        engine=RealWiFiEngine();engine.os_type='Darwin'
        engine._network_context_raw=lambda interface=None:{'local_ip':local_ip,'network':network,'interface':'en0'}
        return engine

    def wait_for_job(self,engine,job_id,timeout=3):
        import time
        end=time.monotonic()+timeout
        job=engine.local_discovery_status(job_id)
        while job and job['status']=='running' and time.monotonic()<end:
            time.sleep(.01);job=engine.local_discovery_status(job_id)
        return job

    def test_authorization_is_required_and_only_small_private_connected_scope_is_allowed(self):
        engine=self.make_engine()
        try:
            with self.assertRaisesRegex(ValueError,'authorization'):
                engine.start_local_discovery(False)
            engine._network_context_raw=lambda interface=None:{'local_ip':'10.0.0.2','network':'10.0.0.0/16','interface':'en0'}
            with self.assertRaisesRegex(ValueError,'256 addresses'):
                engine.start_local_discovery(True)
        finally:engine.stop()

    def test_active_discovery_lists_only_real_icmp_responders_with_provenance(self):
        engine=self.make_engine()
        engine.ping=lambda host,timeout_ms=750:{'host':host,'reachable':host=='192.168.50.10'}
        try:
            started=engine.start_local_discovery(True)
            result=self.wait_for_job(engine,started['id'])
            self.assertEqual(result['status'],'completed')
            self.assertEqual(result['scope'],'192.168.50.8/30')
            self.assertEqual(result['total'],1)
            self.assertEqual([x['ip'] for x in result['results']],['192.168.50.10'])
            self.assertEqual(result['results'][0]['source'],'ICMP echo response')
            self.assertEqual(result['results'][0]['status'],'responded')
            self.assertIsNone(result['results'][0]['mac'])
            self.assertTrue(result['results'][0]['observed_at'])
            self.assertIn('non-response does not mean',result['limitations'][0])
        finally:engine.stop()

    def test_active_scan_can_be_cancelled(self):
        import threading
        engine=self.make_engine(network='192.168.50.0/24',local_ip='192.168.50.9')
        gate=threading.Event()
        engine.ping=lambda host,timeout_ms=750:(gate.wait(.15) or {'host':host,'reachable':False})
        try:
            started=engine.start_local_discovery(True)
            self.assertTrue(engine.cancel_local_discovery(started['id']))
            result=self.wait_for_job(engine,started['id'])
            self.assertEqual(result['status'],'cancelled')
        finally:gate.set();engine.stop()

    def test_macos_ping_uses_millisecond_deadline(self):
        engine=self.make_engine();captured={}
        engine._run=lambda command,timeout=8:(captured.update(command=command,timeout=timeout) or (0,'reply',''))
        engine.ping('192.168.50.10',750)
        self.assertEqual(captured['command'],['ping','-n','-c','1','-W','750','192.168.50.10'])

    def test_windows_ping_uses_bounded_native_arguments(self):
        engine=self.make_engine();engine.os_type='Windows';captured={}
        engine._run=lambda command,timeout=8:(captured.update(command=command,timeout=timeout) or (0,'reply',''))
        engine.ping('192.168.50.10',750)
        self.assertEqual(captured['command'],['ping','-n','1','-w','750','192.168.50.10'])

    def test_mac_neighbor_cache_rows_have_query_source_and_timestamp(self):
        from types import SimpleNamespace
        engine=self.make_engine()
        engine.adapter=SimpleNamespace(neighbors=lambda:([{'ip':'192.168.50.10','mac':'AA:BB:CC:DD:EE:FF','state':'observed','interface':'en0'}],None))
        devices=engine.arp_devices()
        self.assertEqual(len(devices),1)
        self.assertEqual(devices[0]['source'],'arp -an')
        self.assertEqual(devices[0]['interface'],'en0')
        self.assertTrue(devices[0]['observed_at'])

    def test_windows_neighbor_cache_parses_real_entries(self):
        engine=self.make_engine();engine.os_type='Windows'
        engine._network_context_raw=lambda interface=None:{'local_ip':'192.168.50.9','gateway':'192.168.50.1','network':'192.168.50.0/24','interface':'Wi-Fi'}
        engine._run=lambda command,timeout=8:(0,'{"IPAddress":"192.168.50.10","LinkLayerAddress":"AA-BB-CC-DD-EE-FF","State":"Reachable","InterfaceAlias":"Wi-Fi"}','')
        devices=engine.arp_devices()
        self.assertEqual(len(devices),1)
        self.assertEqual(devices[0]['mac'],'AA:BB:CC:DD:EE:FF')
        self.assertEqual(devices[0]['source'],'Get-NetNeighbor')
        self.assertEqual(devices[0]['status'],'reachable')
        self.assertTrue(devices[0]['observed_at'])
