import base64,hashlib,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from axiom_agent import browser
from axiom_agent.storage import LocalStore
from axiom_agent.activity import ActivityStore
from test_agent import custom

def file(text='Project Penguin launches November 3.',name='acquisition.txt'):
 raw=text.encode();return dict(name=name,size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),data=base64.b64encode(raw).decode())
class DestinationTests(unittest.TestCase):
 def setUp(self):self.config=browser.validate_settings(dict(enabled=True,internal_domains=['company.com'],partner_domains=['vendor.example'],public_domains=['public.example']))
 def classification(self,host):return browser.destination('https://'+host,self.config)['classification']
 def test_exact_internal(self):self.assertEqual(self.classification('company.com'),'INTERNAL')
 def test_internal_subdomain(self):self.assertEqual(self.classification('internal.company.com'),'INTERNAL')
 def test_malicious_suffix(self):self.assertEqual(self.classification('company.com.attacker.example'),'EXTERNAL')
 def test_partner(self):self.assertEqual(self.classification('api.vendor.example'),'PARTNER')
 def test_external(self):self.assertEqual(self.classification('other.example'),'EXTERNAL')
 def test_public(self):self.assertEqual(self.classification('public.example'),'PUBLIC')
 def test_normalized_hostname(self):
  self.assertEqual(browser.destination('HTTPS://COMPANY.COM.:443',self.config)['origin'],'https://company.com')
  self.assertEqual(browser.hostname('BÜCHER.example'),'xn--bcher-kva.example')
  config=browser.validate_settings(dict(enabled=True,internal_domains=['company.com'],partner_domains=['vendor.company.com'],public_domains=[]))
  self.assertEqual(browser.destination('https://files.vendor.company.com',config)['classification'],'PARTNER')
 def test_invalid_hostnames(self):
  for host in ['company.com/path','company.com@evil.example','*.company.com','company..com','-company.com',' company.com','company.com?token']:
   with self.subTest(host=host),self.assertRaises(ValueError):browser.hostname(host)
 def test_no_sensitive_urls(self):
  for url in ['https://company.com/path','https://company.com/?token=secret','https://user:password@company.com','file:///tmp/a','javascript:alert(1)']:
   with self.assertRaises(ValueError):browser.destination(url,self.config)
 def test_ip_exact_only(self):
  config=browser.validate_settings(dict(enabled=True,internal_domains=['127.0.0.1','::1'],partner_domains=[],public_domains=[]));self.assertEqual(browser.destination('http://[::1]:8877',config)['classification'],'INTERNAL');self.assertEqual(browser.destination('http://127.0.0.1.attacker.example',config)['classification'],'EXTERNAL')
 def test_duplicate_classification_rejected(self):
  with self.assertRaises(ValueError):browser.validate_settings(dict(enabled=True,internal_domains=['company.com'],partner_domains=['company.com'],public_domains=[]))
 def test_settings_schema(self):
  with self.assertRaises(ValueError):browser.validate_settings({**self.config,'shell':'bad'})

class BrowserPolicyTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=LocalStore(self.root)
  browser.configure(self.store,dict(enabled=True,internal_domains=['internal.localhost'],partner_domains=[],public_domains=[]));self.store.save_rules([custom(name='Project Penguin External Protection',action='BLOCK',destinations=['EXTERNAL'],events=['UPLOAD'])])
 def tearDown(self):self.temp.cleanup()
 def evaluate(self,files=None,origin='http://external.localhost:8877',**changes):return browser.evaluate(self.store,{**dict(request_id='request-one',origin=origin,files=files or [file()]),**changes})
 def test_penguin_external_block(self):
  result=self.evaluate();self.assertEqual(result['action'],'BLOCK');self.assertEqual(result['disposition'],'BLOCK');self.assertEqual(result['destination_class'],'EXTERNAL');self.assertEqual(result['policies'][0]['rule_name'],'Project Penguin External Protection')
 def test_same_file_internal_allow(self):self.assertEqual(self.evaluate(origin='http://internal.localhost:8877')['disposition'],'ALLOW')
 def test_allowed_file(self):self.assertEqual(self.evaluate([file('Ordinary fictional meeting agenda.')])['disposition'],'ALLOW')
 def test_warn(self):
  self.store.save_rules([custom(action='WARN')]);self.assertEqual(self.evaluate()['disposition'],'WARN')
 def test_txt_redaction(self):
  self.store.save_rules([custom(transformation='MASK')]);r=self.evaluate();self.assertEqual(r['disposition'],'REDACT');self.assertEqual(base64.b64decode(r['files'][0]['derivative']).decode(),'Project ███████ launches November 3.');self.assertTrue(r['files'][0]['derivative_name'].endswith('.protected.txt'))
 def test_pdf_requires_review(self):
  import fitz
  doc=fitz.open();page=doc.new_page();page.insert_text((40,40),'Project Penguin');raw=doc.tobytes();doc.close()
  payload=dict(name='sample.pdf',size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),data=base64.b64encode(raw).decode());self.store.save_rules([custom()]);r=self.evaluate([payload]);self.assertEqual(r['disposition'],'REVIEW_REQUIRED');self.assertNotIn('derivative',r['files'][0])
 def test_multiple_one_blocked(self):self.assertEqual(self.evaluate([file('Ordinary agenda.'),file()])['disposition'],'BLOCK')
 def test_multiple_allowed(self):self.assertEqual(self.evaluate([file('Agenda.'),file('Notes.')])['disposition'],'ALLOW')
 def test_unsupported_unassessed(self):self.assertEqual(self.evaluate([file(name='unknown.exe')])['disposition'],'UNASSESSED')
 def test_corrupt_pdf_unassessed(self):self.assertEqual(self.evaluate([file(name='broken.pdf')])['disposition'],'UNASSESSED')
 def test_one_unassessed_never_allows(self):self.assertEqual(self.evaluate([file('Agenda.'),file(name='broken.pdf')])['disposition'],'UNASSESSED')
 def test_block_overrides_unassessed(self):self.assertEqual(self.evaluate([file(),file(name='broken.pdf')])['disposition'],'BLOCK')
 def test_changed_hash_rejected(self):
  payload=file();payload['sha256']='0'*64
  with self.assertRaises(ValueError):self.evaluate([payload])
 def test_changed_size_rejected(self):
  payload=file();payload['size']+=1
  with self.assertRaises(ValueError):self.evaluate([payload])
 def test_file_paths_not_allowed(self):
  for payload in [{**file(),'path':'/etc/passwd'},file(name='../secret.txt')]:
   with self.assertRaises(ValueError):self.evaluate([payload])
 def test_invalid_base64(self):
  with self.assertRaises(ValueError):self.evaluate([{**file(),'data':'!'}])
 def test_oversized_file_rejected(self):
  with self.assertRaises(ValueError):self.evaluate([{**file(),'size':21*1024*1024}])
 def test_combined_limit(self):
  with patch.object(browser,'MAX_BYTES',40),self.assertRaises(ValueError):self.evaluate([file(),file()])
 def test_unknown_fields(self):
  with self.assertRaises(ValueError):self.evaluate(shell='bad')
 def test_invalid_request_id(self):
  with self.assertRaises(ValueError):self.evaluate(request_id='../../evil')
 def test_disabled_protection(self):
  browser.configure(self.store,{**browser.settings(self.store),'enabled':False})
  with self.assertRaises(ValueError):self.evaluate()
 def test_policy_revision_changes(self):
  first=self.evaluate()['policy_revision'];self.store.save_rules([custom(action='ALLOW')]);self.assertNotEqual(browser.revision(self.store),first)
 def test_settings_revision_changes(self):
  first=browser.revision(self.store);browser.configure(self.store,{**browser.settings(self.store),'partner_domains':['partner.example']});self.assertNotEqual(browser.revision(self.store),first)
 def test_metadata_privacy(self):
  r=self.evaluate();r.update(id=r['request_id'],source='browser',event='UPLOAD',outcome='UPLOAD_BLOCKED',url='https://external.localhost/private?token=secret',text='Project Penguin launches November 3.')
  saved=ActivityStore(self.root).append(r);self.assertEqual(saved['outcome'],'UPLOAD_BLOCKED');self.assertEqual(saved['destination_hostname'],'external.localhost');raw=(self.root/'activity.sqlite3').read_bytes()
  for forbidden in [b'Project Penguin launches November 3.',b'acquisition.txt',b'token=secret',b'private?']:self.assertNotIn(forbidden,raw)
 def test_no_audit_before_enforcement_receipt(self):self.evaluate();self.assertFalse((self.root/'activity.sqlite3').exists())
 def test_native_response_derivative_budget(self):
  self.store.save_rules([custom()]);r=self.evaluate([file('penguin '+('x'*300000)),file('penguin '+('x'*300000))]);self.assertEqual(r['disposition'],'REVIEW_REQUIRED');self.assertTrue(all('derivative' not in f for f in r['files']))
 def test_parse_error_is_not_allowed_audit(self):
  r=self.evaluate([file(name='broken.pdf')]);r.update(id='failed',source='browser',event='UPLOAD',outcome='UPLOAD_UNASSESSED');self.assertEqual(ActivityStore(self.root).append(r)['action'],'UNASSESSED')
