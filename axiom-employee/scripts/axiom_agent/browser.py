"""Local browser boundary policy adapter. No URLs, file paths or content in audit."""
import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from .models import ContentEvent, ACTIONS
from .pipeline import Pipeline
from .extraction import MAX_BYTES, ExtractionError

CLASSES = {'INTERNAL', 'PARTNER', 'EXTERNAL', 'PUBLIC'}
DEFAULT = dict(enabled=True, internal_domains=[], partner_domains=[], public_domains=[])

def hostname(value):
    if not isinstance(value,str) or not value or len(value)>253 or value!=value.strip() or any(c in value for c in '/\\@?#%*'):
        raise ValueError('Invalid destination hostname')
    value=value.rstrip('.').lower()
    try:return str(ipaddress.ip_address(value))
    except ValueError:pass
    try:value=value.encode('idna').decode('ascii')
    except UnicodeError:raise ValueError('Invalid destination hostname') from None
    if not value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
        raise ValueError('Invalid destination hostname')
    return value

def destination(value,settings):
    if not isinstance(value,str) or len(value)>512:raise ValueError('Invalid destination origin')
    try:
        url=urlsplit(value)
        if url.scheme not in {'http','https'} or not url.hostname or url.username or url.password or url.path not in {'','/'} or url.query or url.fragment:
            raise ValueError('Invalid destination origin')
        host=hostname(url.hostname);port=url.port
    except (ValueError,TypeError):raise ValueError('Invalid destination origin') from None
    origin=f'{url.scheme}://'+(f'[{host}]' if ':' in host else host)
    if port and port!=({'http':80,'https':443}[url.scheme]):origin+=f':{port}'
    matches=[]
    for key,kind in [('internal_domains','INTERNAL'),('partner_domains','PARTNER'),('public_domains','PUBLIC')]:
        for trusted in settings[key]:
            # IP addresses only match exactly. Domains match on a complete label boundary.
            if host==trusted or (':' not in trusted and not re.fullmatch(r'[0-9.]+',trusted) and host.endswith('.'+trusted)):
                matches.append((len(trusted),kind))
    classification=max(matches,key=lambda item:item[0])[1] if matches else 'EXTERNAL'
    return dict(origin=origin,hostname=host,scheme=url.scheme,classification=classification)

def validate_settings(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULT) or type(value['enabled']) is not bool:raise ValueError('Invalid browser settings')
    result={'enabled':value['enabled']}
    seen=set()
    for key in ['internal_domains','partner_domains','public_domains']:
        items=value[key]
        if not isinstance(items,list) or len(items)>100:raise ValueError('At most 100 domains per classification')
        result[key]=list(dict.fromkeys(hostname(item) for item in items))
        if seen.intersection(result[key]):raise ValueError('A domain cannot have multiple classifications')
        seen.update(result[key])
    return result

def settings(store):
    path=store.root/'browser-settings.json'
    if not path.exists():return dict(DEFAULT)
    if path.stat().st_size>65536:raise ValueError('Browser settings exceed limits')
    return validate_settings(json.loads(path.read_text()))

def configure(store,value):
    value=validate_settings(value)
    fd,name=tempfile.mkstemp(dir=store.root,prefix='.browser-settings-')
    try:
        with os.fdopen(fd,'w') as out:json.dump(value,out)
        os.replace(name,store.root/'browser-settings.json')
    finally:
        if os.path.exists(name):os.unlink(name)
    return value

def revision(store):
    # Bind a decision to local policies AND classification configuration, including edits on disk.
    material=json.dumps([store.rules(),settings(store)],sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(material).hexdigest()

def evaluate(store,payload):
    started=time.monotonic()
    if not isinstance(payload,dict) or set(payload)!={'request_id','origin','files'}:raise ValueError('Invalid browser evaluation schema')
    request_id=payload['request_id']
    if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,100}',request_id):raise ValueError('Invalid request ID')
    config=settings(store)
    if not config['enabled']:raise ValueError('Browser protection is disabled')
    dest=destination(payload['origin'],config)
    files=payload['files']
    if not isinstance(files,list) or not 1<=len(files)<=10:raise ValueError('Select between 1 and 10 files')
    summaries=[];policies={};types=set();total=0;findings=0;actions=[];unassessed=False;review=False;derivative_bytes=0
    rules=store.rules();policy_revision=hashlib.sha256(json.dumps([rules,config],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    for file in files:
        if not isinstance(file,dict) or set(file)!={'name','size','sha256','data'}:raise ValueError('Invalid browser file schema')
        name=file['name'];size=file['size'];digest=file['sha256'];data=file['data']
        if not isinstance(name,str) or not 1<=len(name)<=256 or any(c in name for c in '/\\\0'):raise ValueError('Invalid browser filename')
        if type(size) is not int or not 0<size<=MAX_BYTES or not isinstance(data,str) or len(data)>28*1024*1024:raise ValueError('Browser file exceeds inspection limits')
        if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest):raise ValueError('Invalid file hash')
        try:raw=base64.b64decode(data,validate=True)
        except ValueError:raise ValueError('Invalid browser file encoding') from None
        total+=len(raw)
        if total>MAX_BYTES or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('File changed or exceeds combined inspection limit')
        item={'sha256':digest,'size':size};summaries.append(item)
        try:
            result=Pipeline(rules).scan(name,raw,ContentEvent(id=request_id,source='browser',action='UPLOAD',destination=dest['classification'],destination_domain=dest['hostname'],source_application='Chrome',content_type='document'))
        except ExtractionError:
            unassessed=True;item['status']='UNASSESSED';continue
        except ValueError:
            unassessed=True;item['status']='UNASSESSED';continue
        action=result['action'];actions.append(action);types.add(result['document']['type']);findings+=len(result['detections']);item['status']=action
        for decision in result['decisions']:
            if decision['rule_id'] is not None:policies[decision['rule_id']]={k:decision[k] for k in ('rule_id','rule_name','severity','action')}
        if action=='REDACT':
            if result['document']['type']!='txt':review=True;continue
            protected=''.join(s['text'] for s in result['protected_sections']).encode('utf-8')
            derivative_bytes+=len(protected)
            if derivative_bytes>512*1024:review=True;continue
            item.update(derivative=base64.b64encode(protected).decode(),derivative_name=Path(name).stem+'.protected.txt',derivative_sha256=hashlib.sha256(protected).hexdigest())
    action=max(actions,key=ACTIONS.get) if actions else 'UNASSESSED'
    disposition='BLOCK' if action=='BLOCK' else 'UNASSESSED' if unassessed else 'REVIEW_REQUIRED' if review else action
    if disposition in {'BLOCK','UNASSESSED','REVIEW_REQUIRED'}:
        for item in summaries:
            for key in ('derivative','derivative_name','derivative_sha256'):item.pop(key,None)
    return dict(request_id=request_id,action=action if not unassessed or action=='BLOCK' else 'UNASSESSED',disposition=disposition,
                destination_class=dest['classification'],destination_hostname=dest['hostname'],origin=dest['origin'],files=summaries,
                policies=list(policies.values()),detection_count=findings,document_type=next(iter(types)) if len(types)==1 else 'mixed',
                policy_revision=policy_revision,elapsed_ms=round((time.monotonic()-started)*1000))
