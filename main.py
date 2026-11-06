from __future__ import annotations
import json, os, re, shutil, platform, subprocess, hashlib, threading, uuid, ipaddress, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from core.store import Store
from core.wifi_engine import RealWiFiEngine
from core.dataset_engine import DatasetEngine
from core.assessment_engine import AssessmentEngine
from core.ai_engine import AIEngine
from core.logging_setup import configure as configure_logging
from core.reporting import build_report, write_findings_csv, write_json, write_pdf, write_wifi_audit_pdf
from core.wifi_audit import evaluate as evaluate_wifi_audit, compare_prior_findings
from core.credential_access import CredentialAccessError, retrieve_current_wifi_credential
from core.capture_analysis import capture_size_limit_bytes
from core.capture_storage import import_capture
from core.source_analysis import analyze_files, analyze_repository, MAX_FILE_BYTES, SUPPORTED_SUFFIXES
from core.web_analysis import analyze_site, analyze_url
from core.rogue_ap import compare_access_points, in_wireless_scope, normalize_bssid
from core.device_intelligence import build_profiles
from core.segmentation import evaluate_probe, normalize_plan, probe_tcp
from core.engagement_scope import authorize_execution
from core.attack_paths import build_attack_path_graph
from core.authorization_documents import (copy_authorization_document, delete_authorization_document,
                                          MAX_AUTHORIZATION_DOCUMENT_BYTES, SUPPORTED_AUTHORIZATION_SUFFIXES)
from core.training_simulator import TrainingSessionManager
from core.lan_messaging import DeliveryError, send_announcement, validate_receiver
from core.retesting import classify_finding_retest
from core.catalog import get as catalog_get
try:
 from dotenv import load_dotenv
except ImportError:
 load_dotenv=lambda *a,**k: None
try: import webview
except ImportError: webview=None
def configure_macos_path():
    """Expose standard macOS package-manager paths to Finder-launched apps."""
    if platform.system() != "Darwin":
        return

    candidates = [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/Applications/Wireshark.app/Contents/MacOS",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]

    existing = os.environ.get("PATH", "").split(os.pathsep)
    paths = []

    for path in candidates + existing:
        if path and path not in paths and Path(path).is_dir():
            paths.append(path)

    os.environ["PATH"] = os.pathsep.join(paths)


configure_macos_path()
FROZEN = bool(getattr(sys, 'frozen', False))
RESOURCE_ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
if FROZEN:
 APP = Path.home() / 'Library' / 'Application Support' / 'WiFiSentinel'
else:
 APP = Path(__file__).resolve().parent
APP.mkdir(parents=True, exist_ok=True)
(APP/'data').mkdir(parents=True, exist_ok=True)
(APP/'reports').mkdir(parents=True, exist_ok=True)
(APP/'logs').mkdir(parents=True, exist_ok=True)
configure_logging(APP)
load_dotenv(APP/'.env')
GUI = RESOURCE_ROOT/'gui'/'index.html'
DB = APP/'data'/'wifisentinel.db'
DATA = RESOURCE_ROOT/'data'/'wifi_association_disassociation.csv'
REPORTS = APP/'reports'
CAPTURES = APP/'data'/'captures'
CAPTURES.mkdir(parents=True, exist_ok=True)
AUTHORIZATION_DOCS = APP/'data'/'authorization_documents'
store=Store(DB); store.recover_interrupted_device_discoveries(); store.recover_interrupted_training_sessions(); wifi=RealWiFiEngine(); wifi.set_device_discovery_callback(store.save_device_discovery); dataset=DatasetEngine(DATA)
engine=AssessmentEngine(store,wifi,dataset,nmap_path=shutil.which('nmap')); ai=AIEngine()
wifi_audit_lock=threading.Lock()

def _network_observation_identity(ap):
 if ap.get('bssid'):return f"bssid:{str(ap['bssid']).strip().lower()}|source:{str(ap.get('source') or '').casefold()}"
 keys=('ssid','ssid_observed','ssid_hidden','channel','frequency_ghz','band','signal_dbm','signal_pct',
       'auth','cipher','radio_type','interface','source','observed_at','_observation_index')
 if not any(ap.get(key) not in (None,'') for key in keys):return ''
 return json.dumps([ap.get(key) for key in keys],ensure_ascii=False,separators=(',',':')).casefold()

class Bridge:
 def __init__(self):
  self._capture_lock=threading.RLock(); self._capture_selections={}; self._capture_progress={}; self._source_selections={}; self._source_repository_selections={}; self._authorization_document_selections={}; self._lab_targets=set()
  self._enrolled_receivers={}; self._message_delivery_history=[]; self._retest_lock=threading.RLock(); self._retesting_findings=set()
  self._training_simulator=TrainingSessionManager(
   on_event=lambda sid,event,choice:store.add_training_event(sid,event,choice),
   on_status=lambda sid,status,ended:store.finish_training_session(sid,status,ended))
 def create_lab_targets(self,count=3):
  count=max(1,min(int(count or 3),8)); values=[f'LAB-TARGET-{uuid.uuid4().hex[:8].upper()}' for _ in range(count)]
  self._lab_targets.update(values);return {'data_class':'simulation','targets':values}
 def test_catalog(self,aid=None):return engine.catalog_view(aid)
 def dashboard(self):
  live=self.live_snapshot(); return {'wifi':live.get('wifi',{}),'live':live}
 def wifi_discovery(self):return wifi.poll_refresh().get('wifi',{})
 def live_snapshot(self):
  live=wifi.poll_refresh()
  if not live.get('refreshing'):
   live=dict(live)
   wireless=live['wifi']; attempt=live.get('scan_attempt') or {}
   if attempt.get('status') in {'success','empty'}:
    aps=wireless.get('nearby_aps') if isinstance(wireless.get('nearby_aps'),list) else []
    sources={str(x.get('source') or wireless.get('scan_source') or wireless.get('capability') or 'Operating-system WLAN') for x in aps}
    if not sources:sources={str(wireless.get('scan_source') or wireless.get('capability') or 'Operating-system WLAN')}
    for source in sources:
     rows=[x for x in aps if str(x.get('source') or wireless.get('scan_source') or wireless.get('capability') or 'Operating-system WLAN')==source]
     limitations=list(wireless.get('unavailable_fields') or [])
     if wireless.get('identifier_limitation'):limitations.append(wireless['identifier_limitation'])
     store.save_observation_snapshot({'kind':'wireless','source':source,'method':wireless.get('scan_method') or source,
      'interface':wireless.get('interface') or '', 'status':attempt.get('status'), 'started_at':attempt.get('started_at'),
      'observed_at':wireless.get('observed_at') or attempt.get('successful_at'), 'results':rows,
      'limitations':limitations})
   device_rows=live.get('devices') if isinstance(live.get('devices'),list) else []
   by_source={}
   for row in device_rows:by_source.setdefault(str(row.get('source') or 'OS neighbor cache'),[]).append(row)
   for source,rows in by_source.items():
    store.save_observation_snapshot({'kind':'device','source':source,'method':source,'interface':(live.get('network') or {}).get('interface') or '',
     'status':'observed','observed_at':live.get('observed_at'),'results':rows,
     'limitations':['Neighbor-cache entries do not prove current device availability.']})
  return live
 def observation_history(self,kind=None):return store.observation_history(kind,limit=200)
 def approved_ap_inventory(self):
  try: rows=json.loads(store.setting('approved_ap_inventory','[]'))
  except (ValueError,TypeError): rows=[]
  return [row for row in rows if isinstance(row,dict)] if isinstance(rows,list) else []
 def save_approved_ap(self,bssid,ssid='',notes='',authorized=False):
  if authorized is not True:raise ValueError('Confirm that you are authorized to maintain this approved access-point inventory.')
  normalized=normalize_bssid(bssid)
  inventory=self.approved_ap_inventory()
  record={'bssid':normalized,'ssid':str(ssid or '').strip()[:128], 'notes':str(notes or '').strip()[:500],
   'active':True,'approved_at':datetime.now(timezone.utc).isoformat(timespec='seconds')}
  inventory=[row for row in inventory if str(row.get('bssid') or '').lower()!=normalized]
  inventory.append(record);inventory.sort(key=lambda row:row.get('bssid',''))
  store.set_setting('approved_ap_inventory',json.dumps(inventory,ensure_ascii=False))
  return inventory
 def remove_approved_ap(self,bssid,authorized=False):
  if authorized is not True:raise ValueError('Confirm authorization before changing the approved access-point inventory.')
  normalized=normalize_bssid(bssid);inventory=self.approved_ap_inventory()
  updated=[row for row in inventory if str(row.get('bssid') or '').lower()!=normalized]
  store.set_setting('approved_ap_inventory',json.dumps(updated,ensure_ascii=False));return updated
 def run_rogue_ap_review(self,aid,authorized=False):
  if authorized is not True:raise ValueError('Confirm authorization before reviewing wireless observations.')
  assessment=store.assessment(str(aid or ''))
  if not assessment:raise ValueError('Choose an existing assessment.')
  if not assessment.get('authorization'):raise ValueError('This assessment does not record authorization.')
  if not (assessment.get('wireless_scope') or '').strip():raise ValueError('Declare an SSID or BSSID wireless scope first.')
  snapshot=self.live_snapshot();wifi_state=snapshot.get('wifi') or {};attempt=snapshot.get('scan_attempt') or {}
  if attempt.get('status') not in {'success','empty'} or snapshot.get('refreshing'):
   raise ValueError('A completed current operating-system Wi-Fi scan is required; no review was saved.')
  observations=wifi_state.get('nearby_aps') if isinstance(wifi_state.get('nearby_aps'),list) else []
  scoped=[row for row in observations if in_wireless_scope(row,assessment.get('wireless_scope'))]
  inventory=self.approved_ap_inventory();classified=compare_access_points(scoped,inventory)
  execution=store.start_execution(assessment['id'],'Approved access-point inventory review','rogue_ap_review','local_operator')
  meta={'data_class':'live','scope':assessment.get('wireless_scope'),'scan_status':attempt.get('status'),
   'observed_at':wifi_state.get('observed_at') or attempt.get('successful_at'),'inventory_size':len(inventory),
   'test':'rogue_ap_review','limitations':['An unlisted observation is not proof of an unauthorized access point.',
   'Only BSSIDs explicitly matching this assessment scope are reviewed.',
   'The operating system may omit BSSID, SSID, channel, encryption, or nearby networks.']}
  evidence_id=store.add_evidence(assessment['id'],execution,'wireless_inventory_review',wifi_state.get('scan_source') or 'Operating-system Wi-Fi scan',
   {'inventory':inventory,'observations':classified,'scan_attempt':attempt,'interface':wifi_state.get('interface'),
    'limitations':meta['limitations']},meta,label='Approved access-point inventory comparison',test_id='rogue_ap_review')
  finding_ids=[]
  for item in classified:
   if item['status']!='unlisted':continue
   fid=store.add_finding(assessment['id'],execution,'Unlisted access-point observation', 'Informational',
    'An in-scope operating-system Wi-Fi observation reported a BSSID that is not present in the approved inventory.',
    'The observation may represent an unrecorded authorized access point, a neighboring network included by the OS, or another condition requiring operator validation.',
    'rogue_ap_review','Exact BSSID comparison against the locally maintained approved inventory.',
    'Verify the BSSID with the network owner and update the approved inventory if authorized.',evidence_id,
    confidence='Low',validation='Unverified observation; not a confirmed rogue access point.',asset=item.get('bssid') or 'BSSID unavailable',category='Wireless inventory')
   finding_ids.append(fid)
  store.update_execution(execution,stage='completed',progress=100,status='completed')
  return {'assessment_id':assessment['id'],'execution_id':execution,'evidence_id':evidence_id,
   'observations':classified,'finding_ids':finding_ids,'scan_status':attempt.get('status'),
   'observed_at':meta['observed_at'],'limitations':meta['limitations']}
 def capture_history(self):return store.all_capture_imports(limit=200)
 def capture_analysis(self,capture_id):
  row=store.capture_import(str(capture_id or ''))
  if not row:raise ValueError('Capture evidence was not found.')
  return {'capture_id':row['id'],'assessment_id':row['assessment_id'],'evidence_id':row['evidence_id'],
    'filename':row['filename'],'sha256':row['source_sha256'],'imported_at':row['imported_at'],'analysis':row['analysis']}
 def run_deauth_assessment(self,mode,capture_id=None,ap_ref=None,target_refs=None,authorized=False):
  if mode not in {'passive','simulation'}:return {'status':'Not supported','message':'Live deauthentication and forged-frame transmission are not supported.'}
  if authorized is not True:raise ValueError('Explicit authorization is required.')
  targets=list(dict.fromkeys(str(x) for x in (target_refs or []) if str(x)))
  if not targets:raise ValueError('Select at least one observed target or a generated lab target.')
  if mode=='simulation':
   if any(x not in self._lab_targets for x in targets):raise ValueError('Simulation accepts only generated lab targets from this session.')
   aid=store.setting('offline_capture_assessment_id',''); assessment=store.assessment(aid) if aid else None
   if not assessment:
    assessment=store.create_assessment({'name':'Wireless defense lab simulation','target':'Local software-only simulator','environment':'Simulation',
     'tester':'Local operator','authorization':True,'wireless_scope':'SIMULATION ONLY','authorization_note':'Local software simulation; no radio activity.'})
    aid=assessment['id'];store.set_setting('offline_capture_assessment_id',aid)
   scope=assessment.get('wireless_scope') or 'SIMULATION ONLY'
   result={'mode':'simulation','status':'SIMULATED','target_count':len(targets),'packet_transmission':'none',
    'message':'Software-only training result. No RF frames were created or transmitted.'}
   return store.save_wireless_defense_run(aid,mode,'simulated',scope,targets,result,{'mode':mode,'scope':scope,'targets':targets,'packet_transmission':'none'})
  capture=store.capture_import(str(capture_id or ''))
  if not capture:raise ValueError('Select persisted capture evidence first.')
  assessment=store.assessment(capture['assessment_id'])
  scope=str((assessment or {}).get('wireless_scope') or '').strip()
  if not assessment or not assessment.get('authorization') or not scope:raise ValueError('Passive analysis requires an authorized assessment with an explicit wireless scope.')
  analysis=capture.get('analysis') or {}; management=analysis.get('management_frame_observations') or {}
  ap=str(ap_ref or '').strip().upper()
  if not ap or not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',ap):raise ValueError('Choose an observed BSSID from this capture.')
  declared={x.strip().casefold() for x in scope.replace(';',',').split(',') if x.strip()}
  bssid_in_scope=ap.casefold() in declared
  ssid_in_scope=any(str(row.get('bssid') or '').upper()==ap and str(row.get('ssid') or '').casefold() in declared
    for row in analysis.get('ssid_observations',[]))
  if not (bssid_in_scope or ssid_in_scope):raise ValueError('Selected AP is outside the declared SSID/BSSID scope.')
  observed=set()
  for frame_type in ('deauthentication','disassociation'):
   for row in management.get(frame_type,[]):
    if str(row.get('bssid') or '').upper()==ap:
     observed.update(str(row.get(key) or '').upper() for key in ('transmitter','receiver') if row.get(key))
  if not set(x.upper() for x in targets).issubset(observed):raise ValueError('Every selected target must occur in the selected AP management-frame evidence.')
  pmf_records=management.get('rsn_pmf_advertisements') or {}
  pmf=next((value for key,value in pmf_records.items() if str(key).upper()==ap),
   {'advertised_capable':None,'advertised_required':None,'negotiated_or_enforced':'unknown'})
  deauth=[x for x in management.get('deauthentication',[]) if str(x.get('bssid') or '').upper()==ap]
  disassoc=[x for x in management.get('disassociation',[]) if str(x.get('bssid') or '').upper()==ap]
  def count_for(field):return sum(int(value) for key,value in (management.get(field+'_by_bssid') or {}).items() if str(key).upper()==ap)
  result={'mode':'passive','status':'ANALYSIS COMPLETED','ap_bssid':ap,'target_count':len(targets),
   'targets':targets,'deauthentication_frames_observed':count_for('deauthentication'),'disassociation_frames_observed':count_for('disassociation'),
   'pmf':pmf,'negotiated_or_enforced':'unknown','packet_transmission':'none',
   'limitations':['Capture coverage, monitor mode, channel, packet loss and provenance are not independently verified.',
    'Frame observations do not establish malicious intent or successful disruption.',
    'Advertised PMF capability is not proof of negotiated enforcement.']}
  evidence={'mode':'passive','scope':scope,'authorized':True,'authorization_assessment_id':assessment['id'],
   'ap_bssid':ap,'targets':targets,'capture_id':capture['id'],
   'ap_evidence_ref':capture['evidence_id'],'pmf':pmf,'deauthentication':deauth[:100],'disassociation':disassoc[:100]}
  return store.save_wireless_defense_run(assessment['id'],mode,'completed',scope,targets,result,evidence)
 def refresh_live(self):return {'started':wifi.refresh_now()}
 def devices(self):
  snap=wifi.poll_refresh(); return snap.get('devices',[]) if snap.get('ready') else []
 def start_device_discovery(self,authorized):return wifi.start_local_discovery(authorized)
 def device_discovery_status(self,job_id):return wifi.local_discovery_status(job_id)
 def cancel_device_discovery(self,job_id):return {'cancelled':wifi.cancel_local_discovery(job_id)}
 def latest_device_discovery(self):
  runs=store.latest_device_discovery(limit=1);return runs[0] if runs else None
 def device_intelligence(self):
  observations=[];limits={'snapshot':500,'icmp':500,'neighbor':500,'nmap':500};counts={key:0 for key in limits}
  def add_observation(category,record):
   if counts[category]>=limits[category]:return
   observations.append(record);counts[category]+=1
  for snapshot in store.observation_history('device',limit=500):
   for index,row in enumerate(snapshot.get('results') or []):
    if isinstance(row,dict):add_observation('snapshot',{'observation_id':f"{snapshot['id']}:{index}",
     'source':snapshot.get('source'),'method':snapshot.get('method'),'data_class':snapshot.get('data_class'),
     'observed_at':row.get('observed_at') or snapshot.get('observed_at'),
     'first_seen':snapshot.get('first_seen'),'last_seen':snapshot.get('last_seen'),'fields':row})
  discovery_runs=store.latest_device_discovery(limit=100)
  for run in discovery_runs:
   for index,row in enumerate(run.get('results') or []):
    if isinstance(row,dict):add_observation('icmp',{'observation_id':f"{run['id']}:{index}",
     'source':'Authorized ICMP discovery','method':'Bounded ICMP echo','data_class':'live',
     'observed_at':row.get('observed_at') or run.get('finished_at') or run.get('started_at'),
     'first_seen':None,'last_seen':None,'fields':row})
  for row in store.device_observations(limit=500):
   fields={**row,'type':row.get('device_type'),'open_ports':row.get('open_ports') or []}
   add_observation('neighbor',{'observation_id':row.get('id'),'assessment_id':row.get('assessment_id'),
    'source':'Scoped local neighbor-cache assessment','method':'OS neighbor cache',
    'data_class':row.get('data_class') or 'live','observed_at':row.get('observed_at'),
    'first_seen':None,'last_seen':None,'fields':fields})
  for item in store.nmap_observation_evidence(limit=500):
   payload=item.get('payload') or {}
   if not isinstance(payload,dict):continue
   target=payload.get('target')
   add_observation('nmap',{'observation_id':item['id'],'assessment_id':item['assessment_id'],
    'source':'Local Nmap','method':payload.get('method'),'data_class':item.get('data_class') or 'live',
    'observed_at':item.get('created_at'),'fields':{'ip':target,'status':'scanned',
     'open_ports':payload.get('open_ports') or []}})
  profiles=build_profiles(observations)
  profiles.sort(key=lambda row:str(row.get('observed_at') or ''),reverse=True)
  profiles=profiles[:2000]
  return {'profiles':profiles,'observation_count':len(profiles),
   'sources':sorted({row['source'] for row in profiles}),
   'limitations':['Profiles are individual observations and are not merged into permanent device identities.',
    'The view is bounded to 500 records per source and is not a complete network census.',
    'Nmap service/version labels are scanner fingerprints, not authenticated service identities.',
    'Router/DHCP lease integration and mDNS discovery are not implemented.',
    'MAC randomization can cause one physical device to appear as different observations.',
    'An IP or neighbor-cache record does not prove current Wi-Fi association or complete network visibility.']}
 def run_segmentation_reachability(self,aid,targets,ports,destination_segment,expected,authorized=False):
  if authorized is not True:raise ValueError('Confirm authorization before sending TCP reachability probes.')
  assessment=store.assessment(str(aid or ''))
  if not assessment:raise ValueError('Choose an existing assessment.')
  try:plan=normalize_plan(targets,ports,assessment.get('network_scope'),expected,destination_segment)
  except ValueError as exc:raise ValueError(f'Segmentation plan rejected: {exc}') from None
  policy=store.scope_policy(assessment['id'])
  for target in plan['targets']:
   decision=authorize_execution(assessment,policy,'segmentation_reachability',target)
   if not decision['allowed']:raise ValueError(decision['reason'])
  try:source=wifi.network_context(assessment.get('interface') or None) or {}
  except (OSError,RuntimeError):source={}
  execution=store.start_execution(assessment['id'],'Authorized TCP reachability review',
   'segmentation_reachability','local_operator')
  probes=[];findings=[]
  for target in plan['targets']:
   for port in plan['ports']:
    observation=probe_tcp(target,port)
    interpretation=evaluate_probe(observation,plan['expected'])
    row={**observation,**interpretation,'expected':plan['expected'],
     'destination_segment':plan['destination_segment']}
    probes.append(row)
  limitations=['Probes originate from this computer and the reported local interface; source segments cannot be selected remotely.',
   'TCP connect attempts send no application payload and do not assess UDP or application authorization.',
   'A timeout or generic network error is inconclusive and does not prove filtering.',
   'An observed TCP connection proves only that a handshake completed from this source to this target/port at the time of the test.',
   'No VLAN hopping, route bypass, or cross-segment path is inferred.']
  evidence_id=store.add_evidence(assessment['id'],execution,'segmentation_reachability',
   'Local bounded TCP connect probes',{'source_context':{key:source.get(key) for key in ('local_ip','network','interface','gateway')},
    'destination_segment':plan['destination_segment'],'expected_policy':plan['expected'],
    'probes':probes,'limitations':limitations},
   {'data_class':'live','test':'segmentation_reachability','network_scope':assessment.get('network_scope'),
    'permitted_activity':'segmentation_reachability','limits':{'targets':8,'ports':4,'timeout_seconds':0.75}},
   label='Authorized TCP reachability review',test_id='segmentation_reachability')
  for row in probes:
   if not row['mismatch']:continue
   if plan['expected']=='blocked':
    title='TCP reachability observed where policy expected blocking'
    severity='Low'
    description=f"A TCP handshake completed to {row['target']}:{row['port']} from the current host while the configured policy expected it to be blocked."
    impact='This confirms reachability from this source and port only; it does not prove access to application data or a different source segment.'
   else:
    title='Expected TCP service did not accept a connection'
    severity='Informational'
    description=f"The target {row['target']}:{row['port']} returned a closed-port response while the configured policy expected reachability."
    impact='The service may be unavailable or the expected policy may not match the host configuration; this is not evidence of a security bypass.'
   fid=store.add_finding(assessment['id'],execution,title,severity,description,impact,
    'segmentation_reachability','Direct bounded TCP connect result compared with the operator-declared expected policy.',
    'Verify the source and target segments, expected firewall rule, and service state with the network owner.',
    evidence_id,confidence='High',validation='Direct connection result from this host; validate policy and host service state independently.',
    asset=f"{row['target']}:{row['port']}/tcp",category='Segmentation')
   findings.append(fid)
  store.update_execution(execution,stage='completed',progress=100,status='completed')
  return {'assessment_id':assessment['id'],'execution_id':execution,'evidence_id':evidence_id,
   'source_context':{key:source.get(key) for key in ('local_ip','network','interface','gateway')},
   'probes':probes,'finding_ids':findings,'limitations':limitations}
 def network_observation_history(self,requested):
  if not isinstance(requested,dict):return None
  identity=_network_observation_identity(requested)
  if not identity:return None
  key='network_review_'+hashlib.sha256(identity.encode('utf-8')).hexdigest();aid=store.setting(key,'')
  if not aid or not store.assessment(aid):return None
  for item in store.evidence(aid,limit=100):
   if item.get('type')!='wireless_observation':continue
   full=store.evidence_item(aid,item['id'])
   try:review=json.loads(full.get('content') or '{}')
   except (ValueError,TypeError):continue
   return {'assessment_id':aid,'review':review,'evidence_id':item['id']}
  return None
 def confirm_network_capture_authorization(self,aid,authorized):
  valid_ids={value for key,value in store.settings().items() if key.startswith('network_review_')}
  assessment=store.assessment(aid) if isinstance(aid,str) else None
  if aid not in valid_ids or not assessment or not (assessment.get('wireless_scope') or '').strip():
   raise ValueError('Select and review a live access-point observation before authorizing a scoped offline capture.')
  if authorized is not True:raise ValueError('Explicit capture authorization is required.')
  return store.set_authorization(aid,True,note='User confirmed authorization for scoped offline capture review.',authorized_by='Local operator')
 def analyze_network_observation(self,requested):
  if not isinstance(requested,dict):raise ValueError('Select an access point from the current operating-system scan.')
  snapshot=wifi.poll_refresh(); aps=(snapshot.get('wifi') or {}).get('nearby_aps') or []
  for index,item in enumerate(aps):item['_observation_index']=index
  requested_identity=_network_observation_identity(requested)
  matches=[item for item in aps if _network_observation_identity(item)==requested_identity]
  ap=matches[0] if len(matches)==1 else None
  if len(matches)>1:raise ValueError('This source returned indistinguishable BSSID-less observations. Select a fresh row or use an observed BSSID to disambiguate them.')
  if not ap:raise ValueError('That access point is no longer present in the current scan. Rescan and select a fresh observation.')
  observed_at=ap.get('observed_at') or (snapshot.get('wifi') or {}).get('observed_at')
  identity=_network_observation_identity(ap)
  setting_key='network_review_'+hashlib.sha256(identity.encode('utf-8')).hexdigest()
  aid=store.setting(setting_key,'')
  if not aid or not store.assessment(aid):
   target=ap.get('ssid') or ap.get('bssid') or ('Hidden access point' if ap.get('ssid_hidden') else 'Unlabeled access point')
   scope=ap.get('bssid') or ap.get('ssid') or ''
   record=store.create_assessment({'name':f'Network observation · {target[:90]}','target':target,
    'description':'Automatically created passive observation history. Active checks remain blocked until separately authorized.',
    'wireless_scope':scope,'interface':ap.get('interface'),'environment':'Passive OS scan observation','tester':'WiFiSentinel'})
   aid=record['id'];store.set_setting(setting_key,aid)
  auth=str(ap.get('auth') or '').strip();cipher=str(ap.get('cipher') or '').strip()
  low=(auth+' '+cipher).lower()
  if not auth:
   summary='The operating system did not expose the advertised authentication mode. Security cannot be assessed from this scan.'
  elif any(token in low for token in ('open','none','unsecured')):
   summary='The OS scan describes this access point as open or without advertised link authentication. This is an observation, not proof of a misconfiguration or exposure of any specific traffic.'
  elif 'wep' in low or 'tkip' in low or ('wpa' in low and 'wpa2' not in low and 'wpa3' not in low):
   summary='The advertised profile includes legacy WEP, TKIP, or WPA security. Confirm configuration through the authorized AP/controller; the scan alone cannot validate actual enforcement.'
  elif 'wpa3' in low:
   summary='The scan advertises WPA3. The scan does not validate the negotiated cipher, PMF enforcement, credentials, or resistance to attacks.'
  elif 'wpa2' in low:
   summary='The scan advertises WPA2. The scan does not validate the negotiated cipher, password strength, PMF enforcement, or AP configuration.'
  else:
   summary='The operating system reported an authentication value, but this application cannot classify it reliably from the available fields.'
  review={'ssid':ap.get('ssid'),'ssid_observed':ap.get('ssid_observed'),'ssid_hidden':ap.get('ssid_hidden'),
   'bssid':ap.get('bssid'),'auth':ap.get('auth'),'cipher':ap.get('cipher'),'channel':ap.get('channel'),
   'frequency_ghz':ap.get('frequency_ghz'),'band':ap.get('band'),'signal_dbm':ap.get('signal_dbm'),
   'signal_pct':ap.get('signal_pct'),'radio_type':ap.get('radio_type'),'interface':ap.get('interface'),
   'source':ap.get('source'),'scan_method':ap.get('scan_method'),'vendor':ap.get('vendor'),
   'vendor_note':ap.get('vendor_note'),'client_count':ap.get('client_count'),
   'client_count_note':ap.get('client_count_note'),'observed_at':observed_at,
   'pmf':'unknown_not_exposed_by_scan_source','summary':summary,
   'limitations':['Passive operating-system scan only; no connection, frame capture, or active test occurred.',
                  'Client associations and PMF are not exposed by this source. Advertised security is not proof of runtime configuration.']}
  execution=store.start_execution(aid,'Passive advertised-security review','network_advertisement',started_by='network_dashboard')
  store.add_network(aid,ap)
  evidence=store.add_evidence(aid,execution,'wireless_observation',ap.get('source') or 'Operating-system Wi-Fi scan',review,
   {'test':'network_advertisement','interface':ap.get('interface'),'observation_timestamp':observed_at},
   data_class='live',label='Selected access point observation',test_id='network_advertisement')
  store.add_finding(aid,execution,'Advertised Wi-Fi security profile','Informational',summary,
   'This record summarizes advertised scan fields only; it does not establish vulnerability or compromise.',
   'network_advertisement','Classification is based only on OS-reported authentication and cipher fields.',
   'Verify the AP configuration, cipher, PMF, firmware, and access policy through an authorized controller or configuration review.',
   evidence_id=evidence,confidence='Low',validation='Advertised scan observation only',asset=ap.get('bssid') or ap.get('ssid') or '',category='Wireless Security')
  store.event(aid,execution,'observation',f"Selected AP observation saved from {ap.get('source') or 'OS scan'} at {observed_at or 'an unknown time'}.")
  store.update_execution(execution,stage='completed',progress=100,status='completed')
  store.set_status(aid,'completed',completed_at=observed_at or datetime.now(timezone.utc).isoformat(),last_execution_at=observed_at)
  return {'assessment_id':aid,'review':review,'evidence_id':evidence,'execution_id':execution}
 def interfaces(self):return wifi.interfaces()
 def preflight(self,aid):return engine.preflight(aid)
 def create_assessment(self,data):return store.create_assessment(data)
 def update_assessment(self,aid,data):
  values=dict(data or {});policy=values.pop('scope_policy',None)
  updated=store.update_assessment(aid,**values)
  if policy is not None:store.set_scope_policy(aid,policy,changed_by=values.get('authorized_by') or 'local_operator')
  return updated
 def set_scope_policy(self,aid,policy):return store.set_scope_policy(aid,policy)
 def scope_history(self,aid):return store.scope_history(aid)
 def authorization_documents(self,aid):
  aid=self._report_id(aid)
  docs=store.authorization_documents(aid)
  public=[{key:value for key,value in row.items() if key!='stored_path'} for row in docs]
  return {'documents':public,'history':store.authorization_document_history(aid)}
 def select_authorization_document(self,aid):
  aid=self._report_id(aid)
  if not store.assessment(aid):raise ValueError('Assessment not found.')
  if not webview or not getattr(webview,'windows',None):
   return {'ok':False,'error':'Native authorization-document selection is unavailable in this runtime.'}
  try:
   selected=webview.windows[0].create_file_dialog(webview.OPEN_DIALOG,allow_multiple=False,
    file_types=('Authorization documents (*.pdf;*.doc;*.docx;*.txt)',))
   if not selected:return {'ok':False,'cancelled':True}
   raw=Path(selected[0] if isinstance(selected,(tuple,list)) else selected)
   if raw.is_symlink():raise ValueError('Symbolic links are not accepted for authorization documents.')
   path=raw.resolve(strict=True)
   if not path.is_file():raise ValueError('Choose a regular authorization-document file.')
   if path.suffix.lower() not in SUPPORTED_AUTHORIZATION_SUFFIXES:
    raise ValueError('Choose a PDF, DOC, DOCX, or TXT authorization document.')
   info=path.stat()
   if not info.st_size:raise ValueError('Authorization document is empty.')
   if info.st_size>MAX_AUTHORIZATION_DOCUMENT_BYTES:raise ValueError('Authorization document exceeds the 20 MiB size limit.')
   token=uuid.uuid4().hex
   with self._capture_lock:self._authorization_document_selections[token]={'assessment_id':aid,'path':path,'size':info.st_size,'mtime_ns':info.st_mtime_ns}
   return {'ok':True,'selection_id':token,'filename':path.name,'size_bytes':info.st_size,
    'format':path.suffix[1:].upper(),'max_bytes':MAX_AUTHORIZATION_DOCUMENT_BYTES,
    'storage':'local private application data; content is not parsed or shown'}
  except Exception as exc:
   return {'ok':False,'error':str(exc) if isinstance(exc,ValueError) else f'Could not select authorization document ({type(exc).__name__}).'}
 def import_authorization_document(self,selection_id,authorized=False):
  if authorized is not True:raise ValueError('Confirm that this document is appropriate authorization for the assessment.')
  token=str(selection_id or '')
  with self._capture_lock:selection=self._authorization_document_selections.pop(token,None)
  if not selection:raise ValueError('Authorization document selection expired; choose it again.')
  aid=selection['assessment_id']
  if not store.assessment(aid):raise ValueError('Assessment no longer exists.')
  path=selection['path']
  if path.is_symlink() or not path.is_file():raise ValueError('Selected authorization document is no longer a regular file.')
  info=path.stat()
  if info.st_size!=selection['size'] or info.st_mtime_ns!=selection['mtime_ns']:
   raise ValueError('Authorization document changed after selection; choose it again.')
  document=copy_authorization_document(path,AUTHORIZATION_DOCS,aid)
  try:
   record=store.add_authorization_document(aid,document,uploaded_by='local_operator')
  except Exception:
   delete_authorization_document(AUTHORIZATION_DOCS,document['stored_path'])
   raise
  return {key:value for key,value in record.items() if key!='stored_path'}
 def cancel_authorization_document_selection(self,selection_id):
  with self._capture_lock:removed=self._authorization_document_selections.pop(str(selection_id or ''),None)
  return {'cancelled':bool(removed)}
 def remove_authorization_document(self,aid,document_id,authorized=False):
  if authorized is not True:raise ValueError('Confirm removal of the locally stored authorization document.')
  aid=self._report_id(aid);record=store.authorization_document(aid,str(document_id or ''))
  if not record:raise ValueError('Authorization document not found.')
  if record.get('deleted_at'):return {'removed':False,'already_removed':True}
  store.remove_authorization_document(aid,record['id'],changed_by='local_operator')
  removed=delete_authorization_document(AUTHORIZATION_DOCS,record['stored_path'])
  return {'removed':True,'file_removed':removed,'sha256':record['sha256'],
   'message':'Document metadata remains in the audit history; the stored document copy was removed.' if removed else 'Document metadata was removed from the active list; no stored file remained.'}
 def record_authorization(self,aid,authorized,note='',authorized_by=''):return store.set_authorization(aid,authorized,note,authorized_by)
 def assessments(self):return store.assessment_registry()
 def assessment(self,aid):
  result=store.state(aid)
  if result.get('assessment'):result['scope_policy']=store.scope_policy(aid)
  return result
 def execute_assessment(self,aid):return engine.execute(aid)
 def execution(self,exid):return store.execution(exid)
 def events(self,aid):return store.events(aid)
 def findings(self,aid=None):return store.findings(aid)
 def evidence(self,aid):return store.evidence(aid)
 def evidence_item(self,aid,eid):return store.evidence_item(aid,eid)
 def run_test(self,aid,test_id,config=None):return engine.run_test(aid,test_id,config)
 def retest_finding(self,aid,finding_id):
  key=(str(aid or ''),str(finding_id or ''))
  with self._retest_lock:
   if key in self._retesting_findings:return {'error':'This finding already has a retest in progress.'}
   self._retesting_findings.add(key)
  try:return self._retest_finding(*key)
  finally:
   with self._retest_lock:self._retesting_findings.discard(key)
 def _retest_finding(self,aid,finding_id):
  finding=store.finding(str(aid or ''),str(finding_id or ''))
  if not finding:return {'error':'Finding was not found in this assessment.'}
  prior_execution=store.execution(finding.get('execution_id') or '')
  test_id=(prior_execution or {}).get('test_id')
  test=catalog_get(test_id) if test_id else None
  config={}
  prior_evidence=store.evidence_item(aid,finding.get('evidence_id')) if finding.get('evidence_id') else None
  content=(prior_evidence or {}).get('content')
  if isinstance(content,str):
   try:content=json.loads(content)
   except (TypeError,ValueError):content={}
  if not isinstance(content,dict):content={}
  assessment=store.assessment(aid) or {}
  prior_scope=((prior_evidence or {}).get('metadata') or {}).get('scope')
  if test and prior_evidence:
   if test.get('scope_requirement')=='network':current_scope=f"declared network scope: {assessment.get('network_scope') or 'none'}"
   elif test.get('scope_requirement')=='wireless':current_scope=f"declared wireless scope: {assessment.get('wireless_scope') or 'none'}"
   else:current_scope='host observation (no scope required)'
   if not prior_scope or prior_scope!=current_scope:
    result={'status':'blocked','error':'The assessment scope differs from the original evidence scope; this retest cannot compare results.'}
   else:result=None
  else:result={'status':'blocked','error':'Original evidence or its recorded scope is unavailable.'}
  if test_id=='nmap_scan' and result is None:
   target=content.get('target') or content.get('host')
   if not target:
    result={'status':'blocked','error':'The original Nmap target is absent from persisted evidence.'}
   else:
    original_open=content.get('open_ports') if isinstance(content.get('open_ports'),list) else []
    original_ports=sorted({int(row['port']) for row in original_open if isinstance(row,dict)
                           and str(row.get('protocol') or 'tcp').casefold()=='tcp'
                           and str(row.get('port') or '').isdigit()})
    if not original_ports:
     result={'status':'blocked','error':'The original evidence does not identify the TCP ports needed for a targeted retest.'}
    else:config={'target':target,'ports':original_ports}
  elif test_id=='port_assessment' and result is None:
   host=content.get('host');ports=content.get('ports_requested')
   if not host or not isinstance(ports,list) or not ports:
    result={'status':'blocked','error':'The original target and ports are absent from persisted evidence.'}
   else:config={'host':host,'ports':ports}
  if not test:
   result={'status':'blocked','error':'The original execution is not linked to a currently supported test.'}
  elif result is None:
   result=engine.run_test(aid,test_id,config)
  execution_id=result.get('execution_id') if isinstance(result,dict) else None
  evidence_id=result.get('evidence_id') if isinstance(result,dict) else None
  fresh_evidence=store.evidence_item(aid,evidence_id) if evidence_id else None
  evidence_ok=bool(fresh_evidence)
  comparable={**result,'test_id':test_id,'evidence_id':evidence_id if evidence_ok else None} if isinstance(result,dict) else {}
  fresh_content=(fresh_evidence or {}).get('content')
  if isinstance(fresh_content,str):
   try:fresh_content=json.loads(fresh_content)
   except (TypeError,ValueError):fresh_content={}
  if not isinstance(fresh_content,dict):fresh_content={}
  fresh=store.findings_for_execution(aid,execution_id) if execution_id else []
  outcome=classify_finding_retest(finding,comparable,fresh,content,fresh_content)
  record=store.record_finding_retest(aid,finding_id,outcome['status'],execution_id if execution_id else None,
                                     evidence_id if evidence_ok else None,outcome['detail'])
  return {'retest':record,'execution':result,'finding':finding}
 def finding_retests(self,aid,finding_id=None):return store.finding_retests(aid,finding_id)
 def dataset_summary(self):return dataset.summary()
 def dataset_analysis(self,device=None):return dataset.analyze(device)
 def dataset_detection(self,threshold=10):return dataset.detection(int(threshold))
 def ai_status(self):return ai.status()
 def ai_history(self,aid=None,kind=None):return store.ai_analyses(aid,kind=kind)
 def ai_analyze(self,kind,aid=None):
  try:
   if kind=='dataset':
    analysis=dataset.analyze(); compact={'summary':analysis['summary'],'devices':analysis['devices'][:25],'windows':analysis['windows'][:250]}; result=ai.dataset(compact,dataset.detection())
   else:
    if not aid:return {'ok':False,'error':'Open an assessment before running this AI analysis.'}
    state=store.state(aid)
    if kind=='assessment':result=ai.assessment(state)
    elif kind=='posture':result=ai.posture(state)
    elif kind=='report':result=ai.report(state)
    elif kind.startswith('finding:'):
     fid=kind.split(':',1)[1]; finding=next((x for x in state['findings'] if x['id']==fid),None)
     if not finding:return {'ok':False,'error':'Finding not found.'}
     result=ai.finding(finding,state['evidence'])
    else:return {'ok':False,'error':'Unknown AI analysis.'}
   if result.get('ok'):
    saved=store.save_ai_analysis(None if kind=='dataset' else aid,kind,result.get('model',ai.model),json.dumps(result['result'],ensure_ascii=False))
    result['saved_id']=saved['id']
   return result
  except ValueError as e:return {'ok':False,'error':str(e)}
  except Exception as e:return {'ok':False,'error':f'Could not open the selected local capture ({type(e).__name__}). Check that the file is still available and readable.'}
 def tool_matrix(self):
  definitions=[
   ('nmap','Nmap','Authorized host and service discovery','Declared IP/CIDR scope and recorded authorization','--version',True),
   ('tshark','TShark','Offline packet and protocol inspection','Capture file or supported local capture permissions','--version',False),
   ('tcpdump','tcpdump','Packet capture and inspection','Interface support and operating-system capture permissions','--version',False),
   ('aircrack-ng','Aircrack-ng','Authorized wireless capture analysis','Compatible capture format; no live radio claim','--help',False),
   ('hcxpcapngtool','hcxtools','Wireless capture conversion and analysis','Compatible capture format','--help',False),
   ('bettercap','Bettercap','Network reconnaissance and assessment utility','Explicit scope and platform permissions','-version',False),
   ('wireshark','Wireshark','Packet inspection GUI','Wireshark desktop installation','--version',False),
  ]
  rows=[]
  for executable,label,purpose,prerequisites,version_arg,integrated in definitions:
   path=shutil.which(executable); version=None; detail='Executable was not found on this computer.'
   status='NOT INSTALLED'; code=None
   if path:
    try:
     result=subprocess.run([path,version_arg],capture_output=True,text=True,timeout=2,check=False)
     code=result.returncode
     output=(result.stdout or result.stderr).strip().splitlines()
     version=output[0][:180] if output else None
     if code==0:
      status='AVAILABLE · INTEGRATED' if integrated else 'AVAILABLE · DETECTED'
      detail=('Version command succeeded; bounded local Nmap scans are exposed in Assessments.' if integrated else 'Version/help command succeeded; detection does not mean WiFiSentinel invokes this tool.')
     else:
      status='FOUND · CHECK FAILED'; detail=f'Executable was found, but its bounded check exited with status {code}.'
    except subprocess.TimeoutExpired:
     status='FOUND · CHECK TIMED OUT'; detail='Executable was found; the bounded check timed out.'
    except OSError as exc:
     status='FOUND · CHECK FAILED'; detail=f'Executable was found but could not be checked ({type(exc).__name__}).'
   rows.append({'name':label,'executable':executable,'path':path,'version':version,'status':status,
    'purpose':purpose,'prerequisites':prerequisites,'detail':detail,'invoked_by_wifisentinel':bool(integrated and status=='AVAILABLE · INTEGRATED')})
  return {'os':platform.system(),'local':rows,'catalog_integrates_nmap':True}
 def select_source_files(self):
  """Select local source/configuration files for read-only static review."""
  if not webview or not getattr(webview,'windows',None):
   return {'ok':False,'error':'Native source-file selection is unavailable in this runtime.'}
  try:
   selected=webview.windows[0].create_file_dialog(webview.OPEN_DIALOG,allow_multiple=True,
      file_types=('Source and configuration files (*.py;*.js;*.ts;*.json;*.yaml;*.yml;*.toml;*.env;*.sh)',))
   if not selected:return {'ok':False,'cancelled':True}
   if len(selected)>100:raise ValueError('Select no more than 100 files per review.')
   paths=[]; total=0
   for raw in selected:
    path=Path(raw).resolve(strict=True)
    original=Path(raw)
    if original.is_symlink() or not path.is_file():raise ValueError('Choose regular files; symbolic links are not followed.')
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:raise ValueError(f'Unsupported source file type: {path.suffix or "no extension"}.')
    size=path.stat().st_size
    if size>MAX_FILE_BYTES:raise ValueError(f'{path.name} exceeds the 2 MiB per-file limit.')
    total+=size
    if total>10*1024*1024:raise ValueError('Selected source files exceed the 10 MiB total limit.')
    paths.append(path)
   if not paths: return {'ok':False,'cancelled':True}
   token=uuid.uuid4().hex
   with self._capture_lock:self._source_selections[token]=paths
   return {'ok':True,'selection_id':token,'files':[{'name':p.name,'size_bytes':p.stat().st_size} for p in paths],
           'total_bytes':total,'limit_bytes':10*1024*1024,'execution':'read-only; files are not executed'}
  except Exception as exc:
   return {'ok':False,'error':str(exc) if isinstance(exc,ValueError) else f'Could not select source files ({type(exc).__name__}).'}
 def analyze_source_selection(self,selection_id,authorized=False):
  if authorized is not True:raise ValueError('Confirm that you own or are authorized to review these source files.')
  token=str(selection_id or '')
  with self._capture_lock:paths=self._source_selections.pop(token,None)
  if not paths:raise ValueError('Source selection expired; choose the files again.')
  inputs=[]
  for path in paths:
   if path.is_symlink() or not path.is_file():raise ValueError('A selected file is no longer a regular file.')
   if path.stat().st_size>MAX_FILE_BYTES:raise ValueError(f'{path.name} changed and exceeds the per-file limit.')
   try:
    content=path.read_text(encoding='utf-8')
   except UnicodeDecodeError:
    content=None
   inputs.append({'path':path.name,'content':content})
  result=analyze_files(inputs)
  stamp=datetime.now(timezone.utc).isoformat(timespec='seconds')
  assessment=store.create_assessment({'name':f'Static source review · {stamp[:10]}',
   'target':', '.join(item['path'] for item in result['files'][:5]) or 'Selected local source files',
   'description':'Read-only static source review. No code was executed.', 'environment':'Local source review',
   'tester':'Local operator','authorization':True,
   'authorization_note':'User confirmed ownership or authorization for the selected local source files.',
   'authorized_by':'Local operator'})
  aid=assessment['id']; execution=store.start_execution(aid,'Static source review','source_analysis','local_operator')
  eid=store.add_evidence(aid,execution,'static_source_analysis','Local static source analyzer',result,
   {'data_class':'static_source','test':'source_analysis','execution':'read_only_no_code_execution'},
   data_class='static_source',label=f"{result['files_analyzed']} source file(s) reviewed",test_id='source_analysis')
  for item in result['indicators']:
   store.add_finding(aid,execution,item['title'],item['severity'],
    f"{item['description']} Rule {item['rule_id']} matched {item['path']}:{item['line']}. Excerpt: {item['excerpt']}",
    'A matching source pattern may indicate a security weakness if reachable and improperly controlled.',
    'Static source review',item['rule_id'],item['recommendation'],eid,
    confidence=item['confidence'],validation='Confirm data flow and runtime reachability before treating this indicator as an exploitable vulnerability.',
    asset=item['path'],category='Application Security')
  store.update_execution(execution,'completed',100,'completed')
  store.set_status(aid,'completed',completed_at=store.execution_completed_at(execution))
  store.event(aid,execution,'completed','Static source review completed; no source was executed.')
  return {'ok':True,'assessment_id':aid,'execution_id':execution,'evidence_id':eid,'result':result}
 def select_source_repository(self):
  """Select one local repository directory for bounded, read-only review."""
  if not webview or not getattr(webview,'windows',None):
   return {'ok':False,'error':'Native repository-folder selection is unavailable in this runtime.'}
  try:
   folder_dialog=getattr(getattr(webview,'FileDialog',None),'FOLDER',getattr(webview,'FOLDER_DIALOG',None))
   if folder_dialog is None:raise ValueError('This PyWebView runtime does not expose a folder picker.')
   selected=webview.windows[0].create_file_dialog(folder_dialog)
   if not selected:return {'ok':False,'cancelled':True}
   raw=selected[0] if isinstance(selected,(list,tuple)) else selected
   supplied=Path(raw).expanduser()
   if supplied.is_symlink():raise ValueError('Repository root must not be a symbolic link.')
   root=supplied.resolve(strict=True)
   if not root.is_dir():raise ValueError('Choose a repository directory.')
   token=uuid.uuid4().hex
   with self._capture_lock:self._source_repository_selections[token]=root
   return {'ok':True,'selection_id':token,'name':root.name or 'Selected repository',
           'limits':{'files':500,'total_bytes':25*1024*1024,'file_bytes':MAX_FILE_BYTES},
           'execution':'read-only; source and build files are never executed'}
  except Exception as exc:
   return {'ok':False,'error':str(exc) if isinstance(exc,ValueError) else f'Could not select repository ({type(exc).__name__}).'}
 def analyze_source_repository(self,selection_id,authorized=False):
  if authorized is not True:raise ValueError('Confirm that you own or are authorized to review this repository.')
  token=str(selection_id or '')
  with self._capture_lock:root=self._source_repository_selections.pop(token,None)
  if not root:raise ValueError('Repository selection expired; choose the folder again.')
  result=analyze_repository(root)
  stamp=datetime.now(timezone.utc).isoformat(timespec='seconds')
  assessment=store.create_assessment({'name':f'Static repository review · {stamp[:10]}',
   'target':str(result['files_analyzed'])+' bounded repository files',
   'description':'Read-only static repository review and dependency-manifest inventory. No project code or build scripts were executed.',
   'environment':'Local source review','tester':'Local operator','authorization':True,
   'authorization_note':'User confirmed ownership or authorization for this selected repository.',
   'authorized_by':'Local operator'})
  aid=assessment['id'];execution=store.start_execution(aid,'Static repository review','repository_analysis','local_operator')
  eid=store.add_evidence(aid,execution,'static_repository_analysis','Local static repository analyzer',result,
   {'data_class':'static_source','test':'repository_analysis','execution':'read_only_no_code_execution'},
   data_class='static_source',label=f"{result['files_analyzed']} repository file(s) reviewed",test_id='repository_analysis')
  for item in result['indicators']:
   store.add_finding(aid,execution,item['title'],item['severity'],
    f"{item['description']} Rule {item['rule_id']} matched {item['path']}:{item['line']}. Excerpt: {item['excerpt']}",
    'A matching source pattern may indicate a security weakness if reachable and improperly controlled.',
    'Static repository review',item['rule_id'],item['recommendation'],eid,
    confidence=item['confidence'],validation='Confirm data flow and runtime reachability before treating this indicator as an exploitable vulnerability.',
    asset=item['path'],category='Application Security')
  store.update_execution(execution,'completed',100,'completed')
  store.set_status(aid,'completed',completed_at=store.execution_completed_at(execution))
  store.event(aid,execution,'completed','Static repository review completed; no project code or build script was executed.')
  return {'ok':True,'assessment_id':aid,'execution_id':execution,'evidence_id':eid,'result':result}
 def analyze_web_url(self,url,authorized=False):
  if authorized is not True:raise ValueError('Confirm that you own or are authorized to inspect this website.')
  result=analyze_url(url)
  target=result['target_origin']
  assessment=store.create_assessment({'name':'Read-only web surface snapshot','target':target,
   'description':'Single-page, same-origin GET inspection. No forms were submitted and no source code was executed.',
   'environment':'Authorized web surface review','tester':'Local operator','authorization':True,
   'authorization_note':'User confirmed ownership or authorization for this read-only website inspection.',
   'authorized_by':'Local operator','scope_policy':{'active':False,'permitted_activities':[]}})
  aid=assessment['id'];execution=store.start_execution(aid,'Read-only web surface snapshot','web_surface_snapshot','local_operator')
  evidence=store.add_evidence(aid,execution,'web_surface_snapshot','Authorized same-origin HTTP GET',result,
   {'data_class':'black_box','test':'web_surface_snapshot','http_method':'GET','forms_submitted':False},
   data_class='black_box',label='Read-only web surface snapshot',test_id='web_surface_snapshot')
  for item in result['indicators']:
   store.add_finding(aid,execution,item['title'],item['severity'],item['description'],
    'Observed response metadata may identify a configuration gap; this single response does not demonstrate exploitation.',
    'Read-only web surface snapshot',item['rule_id'],item['recommendation'],evidence,
    confidence=item['confidence'],validation='Confirm configuration and behavior with the application owner before treating this as a vulnerability.',
    asset=target,category='Application Security')
  store.update_execution(execution,'completed',100,'completed')
  store.set_status(aid,'completed',completed_at=store.execution_completed_at(execution))
  store.event(aid,execution,'completed','Read-only same-origin GET completed; forms were not submitted.')
  return {'ok':True,'assessment_id':aid,'execution_id':execution,'evidence_id':evidence,'result':result}
 def analyze_web_site(self,url,max_pages=10,authorized=False):
  if authorized is not True:raise ValueError('Confirm that you own or are authorized to inspect this website.')
  result=analyze_site(url,max_pages=max_pages)
  target=result['target_origin']
  assessment=store.create_assessment({'name':'Bounded read-only web crawl','target':target,
   'description':'Bounded same-origin GET crawl. No forms were submitted, no authenticated session was used, and no source code was executed.',
   'environment':'Authorized web surface review','tester':'Local operator','authorization':True,
   'authorization_note':'User confirmed ownership or authorization for this bounded read-only website inspection.',
   'authorized_by':'Local operator','scope_policy':{'active':False,'permitted_activities':[]}})
  aid=assessment['id'];execution=store.start_execution(aid,'Bounded read-only web crawl','web_surface_crawl','local_operator')
  evidence=store.add_evidence(aid,execution,'web_surface_crawl','Authorized same-origin HTTP GET',result,
   {'data_class':'black_box','test':'web_surface_crawl','http_method':'GET','forms_submitted':False,
    'max_pages':result['max_pages']},data_class='black_box',label='Bounded same-origin web crawl',test_id='web_surface_crawl')
  for item in result['indicators']:
   store.add_finding(aid,execution,item['title'],item['severity'],
    f"{item['description']} Observed on {item['path']}; rule {item['rule_id']}.",
    'Observed response metadata may identify a configuration gap; this read-only inspection does not demonstrate exploitation.',
    'Bounded read-only web crawl',item['rule_id'],item['recommendation'],evidence,
    confidence=item['confidence'],validation='Confirm configuration and behavior with the application owner before treating this indicator as a vulnerability.',
    asset=target+item['path'],category='Application Security')
  store.update_execution(execution,'completed',100,'completed')
  store.set_status(aid,'completed',completed_at=store.execution_completed_at(execution))
  store.event(aid,execution,'completed','Bounded same-origin GET crawl completed; forms were not submitted.')
  return {'ok':True,'assessment_id':aid,'execution_id':execution,'evidence_id':evidence,'result':result}
 def attack_path_analysis(self,aid):
  assessment_id=str(aid or '').strip()
  if not assessment_id or not store.assessment(assessment_id):raise ValueError('Select an existing assessment.')
  evidence=store.evidence(assessment_id,limit=500)
  findings=store.findings(assessment_id)
  return build_attack_path_graph(findings,evidence)
 def start_awareness_training(self,duration_seconds=900):
  session=self._training_simulator.start_session(duration_seconds)
  try:
   store.create_training_session(session['session_id'],session['token_sha256'],session['host'],session['port'],
                                 session['created_at'],session['expires_at'])
  except Exception:
   self._training_simulator.stop_session()
   raise
  return {**self._training_simulator.summary(),'url':session['url'],'duration_seconds':session['duration_seconds']}
 def stop_awareness_training(self):
  return self._training_simulator.stop_session('stopped')
 def awareness_training_summary(self):
  return self._training_simulator.summary()
 def awareness_training_history(self):
  return store.training_sessions()
 def purge_awareness_training_history(self,retention_days=90):
  days=max(30,min(int(retention_days),3650))
  cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat(timespec='seconds')
  return {'deleted_sessions':store.purge_training_sessions_before(cutoff),'retention_days':days}
 def enroll_lan_receiver(self,name,endpoint,token,certificate_sha256,receiver_id,authorized=False):
  if authorized is not True:raise ValueError('Confirm that you administer or are authorized to enroll this receiver.')
  receiver=validate_receiver(name,endpoint,token,certificate_sha256,receiver_id)
  enrollment_id='RCV-'+uuid.uuid4().hex[:12].upper()
  self._enrolled_receivers[enrollment_id]=receiver
  return {'enrollment_id':enrollment_id,'name':receiver['name'],'endpoint':receiver['endpoint'],
          'receiver_id':receiver['receiver_id'],'certificate_sha256':receiver['certificate_sha256'],
          'token_sha256':hashlib.sha256(receiver['token'].encode('utf-8')).hexdigest(),
          'storage':'in-memory only; re-enroll after restarting WiFiSentinel'}
 def enrolled_lan_receivers(self):
  return [{'enrollment_id':key,'name':value['name'],'endpoint':value['endpoint'],
           'receiver_id':value['receiver_id'],'certificate_sha256':value['certificate_sha256']}
          for key,value in self._enrolled_receivers.items()]
 def forget_lan_receiver(self,enrollment_id):
  return self._enrolled_receivers.pop(str(enrollment_id or ''),None) is not None
 def send_lan_announcement(self,enrollment_id,title,body,authorized=False):
  if authorized is not True:raise ValueError('Confirm authorization before sending this announcement.')
  receiver=self._enrolled_receivers.get(str(enrollment_id or ''))
  if not receiver:raise ValueError('Enroll a compatible receiver before sending an announcement.')
  content_hash=hashlib.sha256((str(title)+'\0'+str(body)).encode('utf-8')).hexdigest()
  try:
   result=send_announcement(receiver,title,body)
   record={'ok':True,'status':'acknowledged','message_id':result['message_id'],
           'receiver_id':result['receiver_id'],'receiver_name':receiver['name'],
           'received_at':result['received_at'],'sent_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
           'content_sha256':content_hash,'delivery_claim':result['delivery_claim']}
  except (DeliveryError,ValueError) as exc:
   record={'ok':False,'status':'not_acknowledged','receiver_id':receiver['receiver_id'],
           'receiver_name':receiver['name'],'reason':str(exc),
           'sent_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
           'content_sha256':content_hash}
  self._message_delivery_history.append(record)
  self._message_delivery_history=self._message_delivery_history[-200:]
  return dict(record)
 def lan_message_history(self):
  return [dict(item) for item in reversed(self._message_delivery_history)]
 def _capture_assessment(self,aid):
  aid=self._report_id(aid); assessment=store.assessment(aid)
  if not assessment.get('authorization'):
   raise ValueError('Record explicit assessment authorization before associating a capture with this assessment.')
  if not (assessment.get('wireless_scope') or '').strip():
   raise ValueError('Declare an exact SSID or BSSID scope before reviewing a capture in this assessment.')
  return aid,assessment
 def select_capture(self,aid=None):
  try:
   if aid:
    self._capture_assessment(aid)
   if not webview or not getattr(webview,'windows',None):
    return {'ok':False,'error':'Native capture-file selection is unavailable in this runtime.'}
   selected=webview.windows[0].create_file_dialog(webview.OPEN_DIALOG,allow_multiple=False,
       file_types=('Packet captures (*.pcap;*.pcapng)',))
   if not selected:return {'ok':False,'cancelled':True}
   selected_path=Path(selected[0] if isinstance(selected,(tuple,list)) else selected).resolve(strict=True)
   if not selected_path.is_file():raise ValueError('Selected capture is not a regular file.')
   if selected_path.suffix.lower() not in {'.pcap','.pcapng'}:raise ValueError('Choose a .pcap or .pcapng capture file.')
   stat=selected_path.stat()
   if not stat.st_size:raise ValueError('Capture file is empty.')
   size_limit=capture_size_limit_bytes()
   if stat.st_size>size_limit:raise ValueError(f'Capture exceeds the {size_limit//(1024*1024)} MiB offline-analysis limit.')
   selection_id=uuid.uuid4().hex
   with self._capture_lock:
    self._capture_selections[selection_id]={'path':selected_path,'size':stat.st_size,'mtime_ns':stat.st_mtime_ns,'aid':aid}
    self._capture_progress[selection_id]={'stage':'selected','packets_examined':0}
   return {'ok':True,'selection_id':selection_id,'filename':selected_path.name,'size_bytes':stat.st_size,
           'format_from_extension':selected_path.suffix.lower().lstrip('.'),'maximum_size_bytes':size_limit}
  except Exception as e:return {'ok':False,'error':str(e)}
 def cancel_capture_selection(self,selection_id):
  with self._capture_lock:
   selection=self._capture_selections.get(str(selection_id or ''))
   if not selection:return {'cancelled':False,'error':'Capture selection expired; select the file again.'}
   if selection.get('running'):return {'cancelled':False,'error':'Analysis has already started.'}
   self._capture_selections.pop(str(selection_id),None); self._capture_progress.pop(str(selection_id),None)
  return {'cancelled':True}
 def capture_progress(self,selection_id):
  with self._capture_lock:return dict(self._capture_progress.get(str(selection_id or ''),{'stage':'unknown'}))
 def analyze_capture_selection(self,selection_id,authorized=False,wireless_scope=''):
  token=str(selection_id or '')
  try:
   if authorized is not True:raise ValueError('Confirm authorization before analyzing a selected capture.')
   scope=str(wireless_scope or '').strip()
   aid=store.setting('offline_capture_assessment_id','')
   assessment=store.assessment(aid) if aid else None
   if not assessment or not assessment.get('authorization') or (assessment.get('wireless_scope') or '')!=scope:
    label='Offline capture review'
    assessment=store.create_assessment({'name':label,'target':'User-selected offline capture','environment':'Offline analysis',
      'tester':'Local operator','authorization':True,'wireless_scope':scope,'authorization_note':'User confirmed authorization for local offline capture analysis.',
      'authorized_by':'Local operator'})
    aid=assessment['id'];store.set_setting('offline_capture_assessment_id',aid)
   with self._capture_lock:
    selection=self._capture_selections.get(token)
    if not selection or (selection.get('aid') and selection.get('aid')!=aid):raise ValueError('Capture selection expired; select the file again.')
    if selection.get('running'):raise ValueError('This capture is already being analyzed.')
    selection['running']=True; self._capture_progress[token]={'stage':'copying','packets_examined':0,
       'bytes_copied':0,'bytes_total':selection['size']}
   current=selection['path'].stat()
   if current.st_size!=selection['size'] or current.st_mtime_ns!=selection['mtime_ns']:
    raise ValueError('Capture changed after selection; select it again before analysis.')
   def report_progress(value):
    with self._capture_lock:self._capture_progress[token]=dict(value)
   saved=import_capture(selection['path'],CAPTURES,store,aid,scope,report_progress)
   persisted_result=saved['capture'].get('analysis') if saved['duplicate'] else saved['result']
   with self._capture_lock:
    self._capture_selections.pop(token,None)
    self._capture_progress[token]={'stage':'complete','packets_examined':persisted_result.get('packets_examined',0)}
   return {'ok':True,'result':persisted_result,'evidence_id':saved['evidence_id'],
           'execution_id':saved['execution_id'],'duplicate':saved['duplicate']}
  except Exception as e:
   detail=str(e) if isinstance(e,(ValueError,RuntimeError)) else 'Local file processing or database storage failed. Check file access and available disk space.'
   with self._capture_lock:
    if token in self._capture_selections:self._capture_selections[token]['running']=False
    if token in self._capture_progress:self._capture_progress[token]={'stage':'failed','error':detail}
   return {'ok':False,'error':f'Capture analysis failed: {type(e).__name__}: {detail}'}
 def system_info(self):return {'python':os.sys.version,'os':os.name,'platform':platform.platform(),'architecture':platform.machine(),'app_dir':str(APP),'data_dir':str(APP/'data'),'reports_dir':str(REPORTS),'logs_dir':str(APP/'logs'),'configuration_file':str(APP/'.env')}
 def platform_capabilities(self):
  host=platform.system(); snap=wifi.poll_refresh(); wlan=(snap.get('wifi') or {})
  if host=='Darwin':interfaces,interface_error=wifi.adapter.interfaces()
  else:interfaces,interface_error=wifi.interfaces(),None
  if wlan.get('state')=='ok':wifi_state='AVAILABLE'
  elif wlan.get('state')=='permission_required':wifi_state='PERMISSION REQUIRED'
  elif wlan.get('state') in {'unsupported_platform','no_wireless_interface','wlan_unavailable','scan_unavailable'}:wifi_state='UNAVAILABLE'
  elif snap.get('refreshing') or not snap.get('ready'):wifi_state='CHECKING'
  else:wifi_state='PARTIAL'
  nmap=next(row for row in self.tool_matrix()['local'] if row['executable']=='nmap')
  return {'os':host,'os_version':platform.version(),'architecture':platform.machine(),'python':platform.python_version(),
   'interfaces':interfaces,'capabilities':[
    {'name':'Wi-Fi discovery','status':wifi_state,'detail':wlan.get('error') or interface_error or wlan.get('state') or 'Awaiting first observation'},
    {'name':'2.4 / 5 GHz coverage','status':'OS / adapter dependent','detail':'The live scan reports only channels returned by the operating system; it does not prove complete band coverage.'},
    {'name':'6 GHz coverage','status':'NOT VERIFIED','detail':'The OS and adapter must explicitly expose 6 GHz channels; interface presence alone does not prove support.'},
    {'name':'Local neighbor discovery','status':'AVAILABLE' if host in {'Windows','Darwin'} and shutil.which('arp') else 'UNAVAILABLE','detail':'Reads the operating-system neighbor cache; this is not a complete connected-client list.'},
    {'name':'Offline PCAP/PCAPNG review','status':'AVAILABLE','detail':'Local bounded Scapy analysis; exact wireless scope and authorization are required.'},
    {'name':'Live packet capture','status':'NOT IMPLEMENTED','detail':'WiFiSentinel does not currently start a live packet capture.'},
    {'name':'Monitor mode','status':'NOT VERIFIED','detail':'WiFiSentinel does not infer monitor-mode support from adapter presence; no live monitor capture is implemented.'},
    {'name':'Frame injection','status':'NOT SUPPORTED','detail':'Forged management-frame transmission is not exposed.'},
    {'name':'Nmap','status':nmap['status'],'detail':nmap['detail']},
    {'name':'OpenAI','status':'CONFIGURED' if ai.status().get('configured') else 'NOT CONFIGURED','detail':ai.status().get('model','')},
   ]}
 def settings(self):return {'theme':store.setting('theme','dark')}
 def set_settings(self,data):
  if isinstance(data,dict) and data.get('theme') in {'dark','light','matrix','retro'}:store.set_setting('theme',data['theme'])
  return self.settings()
 def run_wifi_audit(self,authorization_confirmed=False):
  """Collect current OS Wi-Fi context and one bounded gateway ping after consent."""
  if authorization_confirmed is not True:
   raise ValueError('Explicit authorization is required before running a Wi-Fi audit.')
  if not wifi_audit_lock.acquire(blocking=False):
   raise RuntimeError('A Wi-Fi audit is already running.')
  try:
   info=wifi.wifi_info()
   info=info if isinstance(info,dict) else {}
   interface=info.get('interface')
   network=wifi.network_context(interface)
   network=network if isinstance(network,dict) else {}
   source=(info.get('source') or info.get('scan_source') or info.get('capability')
           or ('macOS CoreWLAN / networksetup' if wifi.os_type=='Darwin' else
               ('Windows WLAN' if wifi.os_type=='Windows' else 'Operating-system Wi-Fi adapter')))
   observed_at=info.get('observed_at') or datetime.now(timezone.utc).isoformat(timespec='seconds')
   context={'wifi':info,'network':network,'source':source,'observed_at':observed_at}
   probe={'status':'unavailable','source':'local OS ping','observed_at':observed_at}
   gateway=network.get('gateway')
   try:
    valid_gateway=str(ipaddress.ip_address(gateway)) if gateway else None
   except ValueError:
    valid_gateway=None
   if info.get('connected') is True and valid_gateway:
    try:
     result=wifi.ping(valid_gateway,timeout_ms=1200)
     probe.update(status='reachable' if result.get('reachable') else 'unreachable',
                  observed_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
    except Exception as exc:
     probe.update(error_type=type(exc).__name__,observed_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
   audit=evaluate_wifi_audit(context,True,probe)
   latest=store.wifi_audits(limit=100)
   current_bssid=str((audit.get('network') or {}).get('bssid') or '').casefold()
   previous=next((row for row in latest if current_bssid and str(((row.get('payload') or {}).get('network') or {}).get('bssid') or '').casefold()==current_bssid),None)
   audit['remediation_verification']=compare_prior_findings(previous,audit) if previous else []
   lifecycle={row.get('check_id'):row.get('status') for row in audit['remediation_verification']}
   for finding in audit.get('findings',[]):
    if lifecycle.get(finding.get('check_id')) in {'still_present','recurring'}:
     finding['status']=lifecycle[finding.get('check_id')]
   return store.save_wifi_audit(audit)
  finally:
   wifi_audit_lock.release()
 def wifi_audit_history(self):
  return store.wifi_audits(limit=100)
 def get_current_wifi_credential(self,reveal_confirmed=False):
  if reveal_confirmed is not True:
   raise ValueError('An explicit action is required before requesting the current network credential.')
  try:
   info=wifi.wifi_info()
   password=retrieve_current_wifi_credential(wifi.os_type,info)
   return {'ok':True,'password':password}
  except CredentialAccessError as exc:
   return {'ok':False,'reason':str(exc)}
  except Exception as exc:
   return {'ok':False,'reason':f'Credential access failed safely: {type(exc).__name__}.'}
 def set_wifi_remediation_applied(self,audit_id,finding_id,applied=True):
  if not isinstance(audit_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',audit_id):
   raise ValueError('Wi-Fi audit was not found.')
  if not isinstance(finding_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',finding_id):
   raise ValueError('Finding was not found.')
  if applied is not True and applied is not False:
   raise ValueError('Applied state must be true or false.')
  return store.set_wifi_audit_remediation(audit_id,finding_id,applied)
 def export_wifi_audit_pdf(self,audit_id):
  try:
   if not isinstance(audit_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',audit_id):
    raise ValueError('Wi-Fi audit was not found.')
   audit=store.wifi_audit(audit_id)
   if not audit:raise ValueError('Wi-Fi audit was not found.')
   if not audit.get('integrity_valid'):raise ValueError('Wi-Fi audit integrity check failed; export is blocked.')
   path=REPORTS/f'{audit_id}_{_export_stamp()}_wifi_audit.pdf'
   return write_wifi_audit_pdf(path,audit)
  except Exception as exc:
   return {'error':f'Wi-Fi audit PDF export failed: {type(exc).__name__}: {exc}'}
 def _report_id(self,aid):
  if not isinstance(aid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',aid) or not store.assessment(aid):
   raise ValueError('Assessment not found.')
  return aid
 def export_json(self,aid):
  try:
   aid=self._report_id(aid); report=self._report_payload(aid); p=REPORTS/f'{aid}_{_export_stamp()}.json'; return write_json(p,report)
  except Exception as e:return {'error':f'JSON export failed: {e}'}
 def export_csv(self,aid):
  try:
   aid=self._report_id(aid); p=REPORTS/f'{aid}_assessment_{_export_stamp()}.csv'
   report=self._report_payload(aid)
   return write_findings_csv(p,report['findings'],store.capture_imports(aid,include_analysis=True),report['report'],
    report.get('wireless_defense_runs'),report.get('observation_snapshots'),report.get('finding_retests'))
  except Exception as e:return {'error':f'CSV export failed: {e}'}
 def _report_payload(self,aid):
  aid=self._report_id(aid); state=store.state(aid,include_all=True); snap=wifi.poll_refresh(); live=snap.get('wifi') or {}
  assessment=state.get('assessment') or {}; wireless_scope={x.strip().casefold() for x in str(assessment.get('wireless_scope') or '').replace(';',',').split(',') if x.strip()}
  network_scope=[]
  for value in str(assessment.get('network_scope') or '').replace(';',',').split(','):
   try:network_scope.append(ipaddress.ip_network(value.strip(),strict=False))
   except ValueError:continue
  scoped_history=[]
  for observation in store.observation_history(limit=1000):
   results=[]
   for item in observation.get('results') or []:
    if observation.get('kind')=='wireless':
     identity={str(item.get('bssid') or '').casefold(),str(item.get('ssid') or '').casefold()}
     if wireless_scope and identity & wireless_scope:results.append(item)
    elif observation.get('kind')=='device' and network_scope:
     try:
      addr=ipaddress.ip_address(item.get('ip'))
      if any(addr.version==net.version and addr in net for net in network_scope):results.append(item)
     except ValueError:continue
   if results:scoped_history.append({**observation,'results':results})
  state['observation_snapshots']=scoped_history
  state['authorization_documents']=[{key:value for key,value in row.items() if key!='stored_path'}
   for row in store.authorization_documents(aid)]
  state['authorization_document_history']=store.authorization_document_history(aid)
  context={'operating_system':platform.platform(),'architecture':platform.machine(),'python':platform.python_version(),
           'interface':state['assessment'].get('interface') or live.get('interface') or 'Not exposed',
           'wifi_state':live.get('state','Not observed'),'wifi_limitation':live.get('error'),
           'data_sources':'Local OS observations and stored assessment evidence.'}
  return build_report(state,context)
 def export_pdf(self,aid):
  try:
   aid=self._report_id(aid); p=REPORTS/f'{aid}_{_export_stamp()}.pdf'; write_pdf(p,self._report_payload(aid)); return str(p)
  except Exception as e:return {'error':f'PDF export failed: {type(e).__name__}: {e}'}

def _export_stamp():return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
def main():
 if not webview:
  raise SystemExit('PyWebView is required. Run the platform launcher so the managed environment can install dependencies.')
 if sys.platform == 'darwin':
  try:
   from core.macos_location import request_location_authorization
   request_location_authorization()
  except Exception as exc:
   print(f'[WiFiSentinel] Location authorization request unavailable: {type(exc).__name__}: {exc}', flush=True)
 wifi.refresh_now()
 webview.create_window('WiFiSentinel — Wireless Security Assessment',url=GUI.as_uri(),width=1480,height=920,min_size=(820,600),resizable=True,js_api=Bridge()); webview.start()
if __name__=='__main__':main()
