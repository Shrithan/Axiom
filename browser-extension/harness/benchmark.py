#!/usr/bin/env python3
"""Measure local bridge assessment only. No form submission or audit commit."""
import argparse,base64,hashlib,json,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'native'))
from host import forward
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--data-dir',type=Path,required=True);args=parser.parse_args();samples=[]
 raw=b'Ordinary fictional meeting agenda.\n'*300
 for _ in range(5):
  identity=str(uuid.uuid4());message=dict(op='evaluate',request_id=identity,payload=dict(request_id=identity,origin='http://internal.localhost:8877',files=[dict(name='benchmark.txt',size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),data=base64.b64encode(raw).decode())]))
  start=time.monotonic();response=forward(message,args.data_dir);elapsed=round((time.monotonic()-start)*1000,1)
  if not response.get('ok'):raise SystemExit('Bridge assessment failed: '+str(response.get('error','unavailable')))
  samples.append(dict(round_trip_ms=elapsed,pipeline_ms=response['result']['elapsed_ms']))
 print(json.dumps(dict(bytes=len(raw),samples=samples,note='Private socket plus Python worker assessment; excludes Chrome/file reading/submission and records no upload outcome.'),indent=2))
