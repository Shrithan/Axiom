#!/usr/bin/env python3
"""Create fresh, isolated test policies and fictional files; never replace user rules."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'axiom-employee/scripts'))
from axiom_agent.storage import LocalStore
from axiom_agent.policy import default_rules
from axiom_agent.browser import configure

def setup(root):
 if root.exists():raise SystemExit('Demo directory exists. Choose a fresh --root directory.')
 root.mkdir(mode=0o700,parents=True)
 store=LocalStore(root/'data');fixtures=root/'fixtures';fixtures.mkdir();watched=root/'watched';watched.mkdir()
 rule=dict(id='demo-penguin',name='Project Penguin External Protection',kind='keyword',pattern='penguin',case_sensitive=False,severity='HIGH',action='BLOCK',transformation='REDACT',replacement='[REMOVED]',enabled=True,destinations=['EXTERNAL'],events=['UPLOAD'])
 warning={**rule,'id':'demo-warning','name':'Fictional review warning','pattern':'review notice','severity':'LOW','action':'WARN'}
 store.save_rules(default_rules()+[rule,warning]);configure(store,dict(enabled=True,internal_domains=['internal.localhost'],partner_domains=[],public_domains=[]))
 path=store.root/'agent-settings.json';path.write_text(json.dumps(dict(protection=True,clipboard=True,files=True,notifications=False,folders=[str(watched)])));path.chmod(0o600)
 for name,text in {'acquisition.txt':'Fictional acquisition memo. Project Penguin launches November 3.\n','agenda.txt':'Ordinary fictional meeting agenda.\n','contact.txt':'Fictional contact: phase3.person@example.com\n','warning.txt':'Fictional review notice.\n'}.items():(fixtures/name).write_text(text)
 return dict(data_dir=str(store.root),fixtures=str(fixtures),watched=str(watched))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,default=Path('/private/tmp/axiom-phase3-demo'));args=parser.parse_args();print(json.dumps(setup(args.root.resolve()),indent=2))
