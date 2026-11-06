import json, tempfile, unittest
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.ai_engine import AIEngine
from core.store import Store

class FakeResponse:
    def __init__(self, payload): self.payload=payload
    def __enter__(self): return self
    def __exit__(self,*a): pass
    def read(self): return json.dumps(self.payload).encode()

class AITests(unittest.TestCase):
    def test_unconfigured_ai_is_explicit(self):
        r=AIEngine(api_key='').dataset({'summary':{},'devices':[],'windows':[]},{'count':0})
        self.assertFalse(r['ok'])
        self.assertIn('OPENAI_API_KEY', r['error'])

    def test_response_json_is_parsed_and_persisted(self):
        payload={'output_text':json.dumps({'executive_summary':'grounded','key_observations':[],'behavioral_signals':[],'device_priorities':[],'validation_actions':[],'limitations':[]})}
        with patch('core.ai_engine.urllib.request.urlopen', return_value=FakeResponse(payload)):
            r=AIEngine(api_key='test-key').dataset({'summary':{},'devices':[],'windows':[]},{'count':0})
        self.assertTrue(r['ok'])
        self.assertEqual(r['result']['executive_summary'],'grounded')

    def test_malformed_and_schema_invalid_ai_responses_are_rejected(self):
        with patch('core.ai_engine.urllib.request.urlopen', return_value=FakeResponse({'output_text':'not json'})):
            malformed=AIEngine(api_key='test-key').dataset({}, {})
        self.assertFalse(malformed['ok'])
        self.assertEqual(malformed['error_code'],'malformed_response')
        with patch('core.ai_engine.urllib.request.urlopen', return_value=FakeResponse({'output_text':'{}'})):
            invalid=AIEngine(api_key='test-key').dataset({}, {})
        self.assertFalse(invalid['ok'])
        self.assertEqual(invalid['error_code'],'schema_violation')

    def test_api_key_is_redacted_from_provider_errors_and_logs(self):
        secret='sk-test-do-not-log'
        error=urllib.error.HTTPError('https://api.openai.com/v1/responses',500,'provider error',{},BytesIO(secret.encode()))
        with patch('core.ai_engine.urllib.request.urlopen',side_effect=error):
            result=AIEngine(api_key=secret).dataset({}, {})
        self.assertNotIn(secret,result['error'])

    def test_ai_history_is_separate_from_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            st=Store(Path(td)/'x.db')
            a=st.create_assessment({'name':'A','authorization':True,'network_scope':'10.0.0.0/24'})
            st.save_ai_analysis(a['id'],'assessment','test','{"executive_summary":"ok"}')
            state=st.state(a['id'])
            self.assertEqual(len(state['ai_analyses']),1)
            self.assertEqual(state['evidence'],[])

if __name__=='__main__': unittest.main()
