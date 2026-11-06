import tempfile
import sqlite3
import unittest
from pathlib import Path

from core.store import SCHEMA_VERSION, Store


class DeviceObservationHistoryTests(unittest.TestCase):
    def test_v6_migration_is_additive_and_preserves_existing_assessment(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'legacy.db'
            conn=sqlite3.connect(path)
            conn.execute('CREATE TABLE assessments(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT,target TEXT,environment TEXT,tester TEXT,authorization INTEGER NOT NULL DEFAULT 0,wireless_scope TEXT,network_scope TEXT,interface TEXT,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,started_at TEXT,completed_at TEXT)')
            conn.execute("INSERT INTO assessments(id,name,status,created_at,updated_at) VALUES ('ASM-KEEP','Existing','ready','2026-01-01','2026-01-01')")
            conn.execute('PRAGMA user_version=6');conn.commit();conn.close()
            store=Store(path)
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(store.assessment('ASM-KEEP')['name'],'Existing')
            self.assertIsNotNone(store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='observation_snapshots'").fetchone())
            store.close()

    def test_snapshots_are_source_specific_and_equivalent_runs_update_last_seen(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / 'history.db')
            wifi = {'kind': 'wireless', 'source': 'macOS CoreWLAN', 'method': 'CoreWLAN scan',
                    'interface': 'en0', 'status': 'success', 'observed_at': '2026-10-14T10:00:00+00:00',
                    'results': [{'ssid': 'Lab', 'bssid': '02:00:00:00:00:01', 'source': 'macOS CoreWLAN'}]}
            first = store.save_observation_snapshot(wifi)
            duplicate = store.save_observation_snapshot({**wifi, 'observed_at': '2026-10-14T10:01:00+00:00'})
            neighbor = store.save_observation_snapshot({'kind': 'device', 'source': 'OS neighbor cache',
                'method': 'neighbor table', 'interface': 'en0', 'status': 'success',
                'observed_at': '2026-10-14T10:02:00+00:00', 'results': [{'ip': '192.0.2.2', 'status': 'stale'}]})
            icmp = store.save_observation_snapshot({'kind': 'device', 'source': 'ICMP echo response',
                'method': 'authorized ICMP', 'interface': 'en0', 'status': 'success',
                'observed_at': '2026-10-14T10:03:00+00:00', 'results': [{'ip': '192.0.2.2', 'status': 'responded'}]})
            history = store.observation_history()
            self.assertEqual(first['id'], duplicate['id'])
            self.assertEqual(first['first_seen'], '2026-10-14T10:00:00+00:00')
            self.assertEqual(duplicate['last_seen'], '2026-10-14T10:01:00+00:00')
            self.assertEqual(len(history), 3)
            self.assertNotEqual(neighbor['source'], icmp['source'])
            self.assertEqual({x['source'] for x in history if x['kind'] == 'device'},
                             {'OS neighbor cache', 'ICMP echo response'})
            store.close()


if __name__ == '__main__':
    unittest.main()
