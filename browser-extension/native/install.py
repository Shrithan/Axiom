#!/usr/bin/env python3
"""Install an exact-origin Native Messaging host manifest for Chrome/Chromium."""
import argparse
import base64
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path

def extension_id(manifest):
    digest=hashlib.sha256(base64.b64decode(manifest['key'])).hexdigest()[:32]
    return ''.join(chr(ord('a')+int(c,16)) for c in digest)

def install(root,browser='chrome',directory=None,data_dir=None):
    native=root/'native'
    wrapper=native/'axiom-native-host'
    script=native/'host.py'
    body='#!/bin/sh\n'
    if data_dir:body+='export AXIOM_DATA_DIR='+shlex.quote(str(Path(data_dir).resolve()))+'\n'
    body+='exec '+shlex.quote(sys.executable)+' '+shlex.quote(str(script.resolve()))+' "$@"\n'
    wrapper.write_text(body);wrapper.chmod(0o700)
    destination=Path(directory) if directory else Path.home()/'Library/Application Support'/('Google/Chrome' if browser=='chrome' else 'Chromium')/'NativeMessagingHosts'
    destination.mkdir(parents=True,exist_ok=True)
    identity=extension_id(json.loads((root/'manifest.json').read_text()))
    manifest=dict(name='com.axiom.browser',description='Axiom local browser privacy bridge',path=str(wrapper.resolve()),type='stdio',allowed_origins=['chrome-extension://'+identity+'/'])
    path=destination/'com.axiom.browser.json';path.write_text(json.dumps(manifest,indent=2)+'\n');path.chmod(0o600)
    return dict(extension_id=identity,manifest=str(path))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--browser',choices=['chrome','chromium'],default='chrome');parser.add_argument('--directory');parser.add_argument('--data-dir');args=parser.parse_args()
    print(json.dumps(install(Path(__file__).resolve().parents[1],args.browser,args.directory,args.data_dir)))
