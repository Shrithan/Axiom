"""Phase 2 pipeline contracts; OS mutation and queue tests live in Rust."""
import base64
import dataclasses
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from axiom_agent.events import normalize_event
from axiom_agent.models import ContentEvent
from axiom_agent.service import Service
from axiom_agent.storage import LocalStore
from axiom_agent.activity import ActivityStore
from test_agent import custom

class EventTests(unittest.TestCase):
    def test_defaults_unique(self):
        a,b=normalize_event({}),normalize_event({})
        self.assertNotEqual(a.id,b.id);self.assertEqual(a.source,'manual')
    def test_file_context(self):
        e=normalize_event(dict(source='filesystem',action='FILE_MODIFIED',destination='UNSPECIFIED',file_path='/tmp/sample.txt'))
        self.assertEqual(e.destination,'UNSPECIFIED')
    def test_clipboard_context(self):
        e=normalize_event(dict(source='clipboard',action='COPY',content_type='text',source_application='Microsoft Excel',source_application_id='com.microsoft.Excel'))
        self.assertEqual(e.source_application_id,'com.microsoft.Excel')
    def test_no_fictional_open(self):
        with self.assertRaises(ValueError):normalize_event(dict(source='filesystem',action='OPEN'))
    def test_invalid_payloads(self):
        for value in ([],None,dict(raw_text='secret'),dict(source='email'),dict(destination='UNKNOWN'),dict(timestamp=float('nan')),dict(timestamp=float('inf')),dict(id=''),dict(file_path='x'*4097)):
            with self.subTest(value=type(value).__name__),self.assertRaises(ValueError):normalize_event(value)
    def test_clipboard_only_text_copy(self):
        for fields in (dict(action='PASTE',content_type='text'),dict(action='COPY',content_type='image')):
            with self.assertRaises(ValueError):normalize_event(dict(source='clipboard',**fields))

class BackgroundTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=LocalStore(self.root);self.service=Service(self.store);self.store.save_rules([custom(transformation='MASK')])
    def tearDown(self):self.temp.cleanup()
    def scan(self,text='Project Penguin launches Friday.',source='clipboard',**changes):
        event=dataclasses.asdict(ContentEvent(source=source,action='COPY' if source=='clipboard' else 'FILE_CREATED',content_type='text' if source=='clipboard' else 'document',destination='UNSPECIFIED'))
        event.update(changes)
        return self.service.handle(dict(op='background_scan',event=event,name='acquisition.txt',data=base64.b64encode(text.encode()).decode()))
    def record(self,result,outcome='CLIPBOARD_REPLACED'):
        return self.service.handle(dict(op='background_record',record={**result,'outcome':outcome}))
    def test_penguin_clipboard_end_to_end(self):
        result=self.scan();self.assertEqual(result['protected_text'],'Project ███████ launches Friday.')
        record=self.record(result);self.assertEqual((record['source'],record['event'],record['action']),('clipboard','COPY','REDACT'))
        self.assertEqual(record['policies'][0]['rule_name'],'Project Penguin');self.assertEqual(record['policies'][0]['severity'],'HIGH')
        self.assertNotIn(b'Project Penguin launches Friday.',(self.root/'activity.sqlite3').read_bytes())
        self.assertNotIn('protected_text',record);self.assertEqual(self.service.handle({'op':'activity_stats'})['protections_applied'],1)
    def test_summary_omits_values(self):
        result=self.scan(source='filesystem');self.assertNotIn('protected_text',result)
        for key in ('detections','file_path','source_application','sections','matched_text'):self.assertNotIn(key,result)
    def test_file_original_untouched(self):
        path=self.root/'acquisition.txt';original=b'Project Penguin launches Friday.';path.write_bytes(original)
        result=self.scan(path.read_text(),source='filesystem',file_path=str(path));self.record(result,'REVIEW_REQUIRED')
        self.assertEqual(path.read_bytes(),original)
    def test_block_has_no_output(self):
        self.store.save_rules([custom(action='BLOCK')]);result=self.scan();self.assertEqual(result['action'],'BLOCK');self.assertNotIn('protected_text',result)
    def test_warn_has_no_output(self):
        self.store.save_rules([custom(action='WARN')]);result=self.scan();self.assertEqual(result['action'],'WARN');self.assertNotIn('protected_text',result)
    def test_allow_has_no_output(self):
        self.store.save_rules([custom(action='ALLOW')]);result=self.scan();self.assertEqual(result['action'],'ALLOW');self.assertNotIn('protected_text',result)
    def test_disabled_rule(self):
        self.store.save_rules([custom(enabled=False)]);result=self.scan();self.assertEqual(result['action'],'ALLOW');self.assertEqual(result['detection_count'],0)
    def test_unspecified_does_not_infer_external(self):
        self.store.save_rules([custom(destinations=['EXTERNAL'])]);self.assertEqual(self.scan()['action'],'ALLOW')
    def test_copy_context_policy(self):
        self.store.save_rules([custom(events=['COPY'])]);self.assertEqual(self.scan()['action'],'REDACT');self.assertEqual(self.scan(source='filesystem')['action'],'ALLOW')
    def test_malformed_document_isolated(self):
        request=dict(op='background_scan',name='bad.pdf',data=base64.b64encode(b'not a pdf').decode(),event=dataclasses.asdict(ContentEvent(source='filesystem',action='FILE_CREATED')))
        with self.assertRaises(ValueError):self.service.handle(request)
        self.assertEqual(self.scan()['action'],'REDACT')
    def test_invalid_encoding_isolated(self):
        with self.assertRaises(ValueError):self.service.handle(dict(op='background_scan',name='a.txt',data='!',event={}))
    def test_metadata_whitelist(self):
        record=self.record({**self.scan(),'file_path':'/secret/penguin.txt','matched_text':'private-value','text':'clipboard-history','filename':'private.docx'})
        self.assertTrue(set(record)<={'id','timestamp','source','event','action','outcome','policies','document_type','detection_count'})
        data=(self.root/'activity.sqlite3').read_bytes()
        for secret in (b'private-value',b'clipboard-history',b'private.docx',b'/secret/'):self.assertNotIn(secret,data)
    def test_unassessed_errors_do_not_claim_allow(self):
        result={**self.scan(),'action':'UNASSESSED','policies':[],'detection_count':0}
        self.assertEqual(self.record(result,'ERROR')['action'],'UNASSESSED')
        with self.assertRaises(ValueError):self.record(result,'CLIPBOARD_REPLACED')
    def test_duplicate_activity_id(self):
        result=self.scan();self.record(result);self.record(result);self.assertEqual(len(self.service.handle({'op':'activity'})),1)
    def test_file_block_is_not_enforcement(self):
        self.store.save_rules([custom(action='BLOCK')]);self.record(self.scan(source='filesystem'),'BOUNDARY_NOT_INTERCEPTED');stats=self.service.handle({'op':'activity_stats'});self.assertEqual(stats['protections_applied'],0);self.assertEqual(stats['files_scanned'],1)
    def test_invalid_record_rejected(self):
        result=self.scan()
        for change in (dict(source='cloud'),dict(outcome='BLOCKED_UPLOAD'),dict(action='FAKE'),dict(id='')):
            with self.assertRaises(ValueError):self.record({**result,**change},change.get('outcome','CLIPBOARD_REPLACED'))
    def test_cross_connection_writes(self):
        records=[{**self.scan(),'id':f'event-{i}','outcome':'WARNED'} for i in range(12)]
        # Initialize schema before concurrent connections.
        ActivityStore(self.root)
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda r:ActivityStore(self.root).append(r),records))
        self.assertEqual(len(ActivityStore(self.root).recent()),12)
    def test_retention_bounds(self):
        store=ActivityStore(self.root);record={**self.scan(),'outcome':'UNCHANGED'}
        # Seed historical metadata, then trigger production retention once.
        with store.connect() as db:
            db.executemany('INSERT INTO activity VALUES (?,?,?)',[(str(i),float(i),json.dumps({**record,'id':str(i),'timestamp':float(i)})) for i in range(2100)])
        store.append(record)
        with store.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM activity').fetchone()[0],2000)
        self.assertEqual(len(store.recent()),200)
    def test_private_audit_permissions(self):
        self.record(self.scan());self.assertEqual((self.root/'activity.sqlite3').stat().st_mode&0o777,0o600)
    def test_rules_changes_affect_background(self):
        self.assertEqual(self.scan()['action'],'REDACT');self.store.save_rules([custom(action='BLOCK')]);self.assertEqual(self.scan()['action'],'BLOCK')

if __name__=='__main__':unittest.main()
