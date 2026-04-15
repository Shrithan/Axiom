#!/usr/bin/env python3
"""Chrome stdio framing -> private Axiom socket. Never logs message bodies."""
import json
import os
import socket
import stat
import struct
import sys
from pathlib import Path
MAX_INPUT=30*1024*1024
MAX_OUTPUT=1024*1024

def read_exact(stream,size):
    chunks=[];remaining=size
    while remaining:
        chunk=stream.read(remaining)
        if not chunk:raise EOFError()
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

def read_message(stream,limit=MAX_INPUT):
    size=struct.unpack('<I',read_exact(stream,4))[0]
    if not 0<size<=limit:raise ValueError('Message exceeds limits')
    value=json.loads(read_exact(stream,size))
    if not isinstance(value,dict):raise ValueError('Invalid message')
    return value

def write_message(stream,value):
    raw=json.dumps(value,separators=(',',':')).encode()
    if len(raw)>MAX_OUTPUT:raise ValueError('Response exceeds limits')
    stream.write(struct.pack('<I',len(raw))+raw);stream.flush()

def expected_origin():
    manifest=json.loads((Path(__file__).resolve().parents[1]/'manifest.json').read_text())
    import base64,hashlib
    digest=hashlib.sha256(base64.b64decode(manifest['key'])).hexdigest()[:32]
    extension_id=''.join(chr(ord('a')+int(c,16)) for c in digest)
    return 'chrome-extension://'+extension_id+'/'

def forward(message,root):
    credential=root/'browser-token';sockpath=root/'browser.sock'
    meta=credential.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('Invalid local credential permissions')
    token=credential.read_text()
    if len(token)!=64:raise ValueError('Invalid local credential')
    meta=sockpath.lstat()
    if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('Invalid local socket permissions')
    body=json.dumps({'token':token,'message':message},separators=(',',':')).encode()
    if len(body)>MAX_INPUT:raise ValueError('Message exceeds limits')
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(35);sock.connect(str(sockpath))
        sock.sendall(struct.pack('<I',len(body))+body)
        with sock.makefile('rb') as stream:return read_message(stream,MAX_OUTPUT)

def main():
    if len(sys.argv)<2 or sys.argv[1]!=expected_origin():return 2
    root=Path(os.environ.get('AXIOM_DATA_DIR',str(Path.home()/'.axiom-local')))
    try:
        while True:
            try:message=read_message(sys.stdin.buffer)
            except EOFError:break
            except (ValueError,UnicodeError):write_message(sys.stdout.buffer,{'request_id':'','ok':False,'error':'INVALID_MESSAGE'});break
            request_id=message.get('request_id','')
            if not isinstance(request_id,str) or len(request_id)>100:request_id=''
            try:result=forward(message,root)
            except (OSError,ValueError,EOFError):result={'request_id':request_id,'ok':False,'error':'AGENT_UNAVAILABLE'}
            write_message(sys.stdout.buffer,result)
    finally:
        try:forward({'op':'disconnect','request_id':'disconnect','payload':None},root)
        except (OSError,ValueError,EOFError):pass
    return 0
if __name__=='__main__':sys.dont_write_bytecode=True;sys.exit(main())
