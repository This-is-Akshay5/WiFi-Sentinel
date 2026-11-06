import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.store import Store


class DefensiveDeauthAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / 'db.sqlite')
        self.assessment = self.store.create_assessment({'name':'Passive review','authorization':True,
            'wireless_scope':'02:00:00:00:00:01'})
        self.analysis = {'management_frame_observations': {
            'deauthentication':[{'bssid':'02:00:00:00:00:01','transmitter':'02:00:00:00:00:01','receiver':'02:00:00:00:00:02','reason_code':7},
                {'bssid':'02:00:00:00:00:01','transmitter':'02:00:00:00:00:01','receiver':'02:00:00:00:00:03','reason_code':7}],
            'disassociation':[], 'protected_management_frames':0,
            'rsn_pmf_advertisements':{'02:00:00:00:00:01':{'advertised_capable':True,'advertised_required':False,'negotiated_or_enforced':'unknown'}}}}
        self.capture = self.store.save_capture_analysis(self.assessment['id'], {'filename':'x.pcap','size_bytes':100,
            'sha256':'f'*64,'capture_format':'pcap','parser_version':'test','packets_examined':1,'candidate_exchanges':0,
            'exchange_pairs':[],'limitations':[],'management_frame_observations':self.analysis['management_frame_observations']},
            'captures/'+'f'*64+'.pcap')
        from main import Bridge
        self.bridge = Bridge()

    def tearDown(self):
        self.store.close(); self.tmp.cleanup()

    def test_passive_assessment_requires_selected_capture_observations_and_keeps_pmfs_unknown(self):
        with patch('main.store',self.store):
            with self.assertRaisesRegex(ValueError,'authorization'):
                self.bridge.run_deauth_assessment('passive',self.capture['capture']['id'],'02:00:00:00:00:01',
                    ['02:00:00:00:00:02'],False)
            run=self.bridge.run_deauth_assessment('passive',self.capture['capture']['id'],'02:00:00:00:00:01',
                ['02:00:00:00:00:02','02:00:00:00:00:03'],True)
            self.assertEqual(run['mode'],'passive')
            self.assertEqual(run['status'],'completed')
            self.assertEqual(run['result']['target_count'],2)
            self.assertEqual(run['result']['pmf']['negotiated_or_enforced'],'unknown')
            self.assertEqual(run['result']['packet_transmission'],'none')
            with self.assertRaisesRegex(ValueError,'outside'):
                self.bridge.run_deauth_assessment('passive',self.capture['capture']['id'],'02:00:00:00:00:03',
                    ['02:00:00:00:00:02'],True)

    def test_live_transmission_is_explicitly_unsupported_and_persists_no_run(self):
        with patch('main.store',self.store):
            result=self.bridge.run_deauth_assessment('live',self.capture['capture']['id'],
                '02:00:00:00:00:01',['02:00:00:00:00:02'],True)
            self.assertEqual(result['status'],'Not supported')
            self.assertEqual(self.store.wireless_defense_runs(self.assessment['id']),[])

    def test_simulation_uses_generated_synthetic_targets_and_explicit_label(self):
        with patch('main.store',self.store):
            targets=self.bridge.create_lab_targets(2)['targets']
            run=self.bridge.run_deauth_assessment('simulation',target_refs=targets,authorized=True)
            self.assertEqual(run['status'],'simulated')
            self.assertEqual(run['result']['packet_transmission'],'none')
            self.assertEqual(run['result']['target_count'],2)
            self.assertEqual(self.store.evidence(run['assessment_id'])[0]['data_class'],'simulation')

    def test_defense_evidence_and_run_roll_back_together(self):
        with patch('main.store',self.store):
            self.store.db.execute("CREATE TRIGGER fail_defense BEFORE INSERT ON wireless_defense_runs BEGIN SELECT RAISE(ABORT,'injected'); END")
            before=len(self.store.evidence(self.assessment['id']))
            with self.assertRaises(Exception):
                self.store.save_wireless_defense_run(self.assessment['id'],'passive','completed','scope',[],{}, {})
            self.assertEqual(len(self.store.evidence(self.assessment['id'])),before)


if __name__ == '__main__': unittest.main()
