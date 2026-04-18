#!/usr/bin/env python3
"""Loopback-only multipart receipt harness. Use fictional fixtures only."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import argparse,hashlib,json,threading
from email.parser import BytesParser
from email.policy import default
COUNTS={};LOCK=threading.Lock();MAX=22*1024*1024
HTML=b'''<!doctype html><meta charset="utf-8"><title>Axiom Upload Boundary Test</title><style>body{font:17px system-ui;max-width:700px;margin:80px auto;background:#111522;color:#eee}button,input{padding:12px;margin:12px 0}form{padding:25px;border:1px solid #866bbd;border-radius:16px}</style><h1>Axiom browser upload boundary</h1><p>This loopback server records only byte counts and SHA-256 hashes. Use fictional fixtures.</p><form action="/upload" method="post" enctype="multipart/form-data"><input aria-label="Upload files" name="files" type="file" multiple required><br><button type="submit">Upload selected files</button></form><p><a style="color:#baabff" href="/stats">Receipt statistics</a></p>'''
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,code,body,kind='application/json'):
  self.send_response(code);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
 def host(self):
  value=self.headers.get('Host','').split(':')[0]
  return value if value in {'external.localhost','internal.localhost','localhost','127.0.0.1'} else None
 def do_GET(self):
  if not self.host():return self.reply(403,b'{}')
  if self.path=='/':return self.reply(200,HTML,'text/html;charset=utf-8')
  if self.path=='/stats':
   with LOCK:body=json.dumps(COUNTS).encode()
   return self.reply(200,body)
  self.reply(404,b'{}')
 def do_POST(self):
  host=self.host()
  if not host or self.path!='/upload':return self.reply(403,b'{}')
  try:size=int(self.headers.get('Content-Length','0'))
  except ValueError:return self.reply(400,b'{}')
  if not 0<size<=MAX:return self.reply(413,b'{}')
  data=self.rfile.read(size);content_type=self.headers.get('Content-Type','')
  message=BytesParser(policy=default).parsebytes(('Content-Type: '+content_type+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+data);files=[]
  if message.is_multipart():
   for part in message.iter_parts():
    if part.get_filename():
     raw=part.get_payload(decode=True) or b'';files.append(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
  with LOCK:
   item=COUNTS.setdefault(host,dict(requests=0,file_bytes=0,files=[]));item['requests']+=1;item['file_bytes']+=sum(f['bytes'] for f in files);item['files'].extend(files);item['files']=item['files'][-200:];body=json.dumps(item).encode()
  self.reply(200,body)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8877);args=parser.parse_args();print('Local upload harness on 127.0.0.1:'+str(args.port),flush=True);ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
