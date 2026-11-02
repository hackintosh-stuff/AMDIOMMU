#!/usr/bin/env python3
"""Bounded F11 ONLY for a software reboot; never touches power GPIO."""
import argparse
import json
from pathlib import Path
import time
import urllib.request
p=argparse.ArgumentParser()
p.add_argument('--stop',required=True)
p.add_argument('--ready',required=True)
a=p.parse_args()
stop,ready=Path(a.stop),Path(a.ready)
assert not stop.exists() and not ready.exists(), 'fresh one-shot paths required'
mode=Path('/etc/kvm/ai-control.mode')
assert mode.read_text().strip()=='mcp', 'manual control is active'
assert Path('/sys/class/gpio/gpio504/value').read_text().strip()=='0', 'host must already be ON'
assert Path('/sys/class/gpio/gpio503/value').read_text().strip()=='0', 'button held'
headers={'Authorization':'Bearer '+json.loads(Path('/etc/kvm/mcp.json').read_text())['apiKey'],'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
counter=0

def rpc(method,params):
    global counter
    counter+=1
    request=urllib.request.Request('http://127.0.0.1/api/mcp',data=json.dumps({'jsonrpc':'2.0','id':counter,'method':method,'params':params}).encode(),headers=headers)
    with urllib.request.urlopen(request,timeout=3) as response:
        sid=response.headers.get('Mcp-Session-Id')
        if sid: headers['Mcp-Session-Id']=sid
        raw=response.read().decode()
    if raw.startswith(('event:','data:')):
        raw=[s[5:].strip() for s in raw.splitlines() if s.startswith('data:')][-1]
    obj=json.loads(raw)
    if obj.get('error') or obj.get('result',{}).get('isError'): raise RuntimeError(str(obj))

rpc('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'round16-f11-only','version':'1'}})
end=time.monotonic()+100
count,failures=0,0
try:
    while time.monotonic()<end and not stop.exists():
        assert mode.read_text().strip()=='mcp', 'manual control took over'
        try:
            rpc('tools/call',{'name':'cube_press_keys','arguments':{'keys':['F11'],'holdMs':800}})
            count+=1
            if not ready.exists(): ready.write_text('F11_READY\n'); print('F11_READY',flush=True)
        except Exception as exc:
            message=str(exc)
            if any(s in message.lower() for s in ('manual','forbidden','401','403')): raise
            failures+=1
            if failures<=3: print('HID_WAIT',message,flush=True)
        time.sleep(.005)
finally:
    stop.touch(exist_ok=True)
    print('F11_STOPPED',count,failures,flush=True)
