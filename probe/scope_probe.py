import base64,hashlib,hmac,json,time,uuid,urllib.request,urllib.error
from urllib.parse import quote, urlsplit
c=json.load(open('/tmp/cred.json')); KEY=c['key']; SEC=c['secret']
def enc(s): return quote(str(s), safe='-_.~')
def call(method,path,body=None):
    url='https://packagist.com'+path; u=urlsplit(url)
    ts=str(int(time.time())); n=uuid.uuid4().hex+uuid.uuid4().hex
    p={'timestamp':ts,'cnonce':n,'key':KEY,'version':'2','query':''}
    if body: p['body']=body
    sts=f"{method}\n{u.hostname}\n{u.path}\n"+"&".join(f"{enc(k)}={enc(v)}" for k,v in sorted(p.items()))
    sig=base64.b64encode(hmac.new(SEC.encode(),sts.encode(),hashlib.sha256).digest()).decode()
    h={'Authorization':f"PACKAGIST-HMAC-SHA256 Key={KEY}, Timestamp={ts}, Cnonce={n}, Version=2, Signature={sig}",
       'Accept':'application/json'}
    if body: h['Content-Type']='application/json'
    r=urllib.request.Request(url,data=body.encode() if body else None,headers=h,method=method)
    try:
        with urllib.request.urlopen(r) as resp: return resp.status, resp.read(300).decode(errors='replace')
    except urllib.error.HTTPError as e: return e.code, e.read(300).decode(errors='replace')
# IN-SCOPE CONTROL first: the artifact-publish endpoint the credential is issued for.
import os
zip_bytes=open('probe/ctl.zip','rb').read()
def upload():
    import urllib.request,urllib.error
    url='https://packagist.com/api/packages/dgseclab%2Fvcs-one/artifacts/'
    u=urlsplit(url); ts=str(int(time.time())); n=uuid.uuid4().hex+uuid.uuid4().hex
    from urllib.parse import quote_from_bytes
    def eb(b):
        if isinstance(b,str): b=b.encode()
        return quote_from_bytes(b,safe='-_.~').encode()
    p={b'timestamp':ts.encode(),b'cnonce':n.encode(),b'key':KEY.encode(),b'version':b'2',b'query':b'',b'body':zip_bytes}
    sts=b'POST\n'+u.hostname.encode()+b'\n'+u.path.encode()+b'\n'+b'&'.join(eb(k)+b'='+eb(v) for k,v in sorted(p.items()))
    sig=base64.b64encode(hmac.new(SEC.encode(),sts,hashlib.sha256).digest()).decode()
    h={'Authorization':f"PACKAGIST-HMAC-SHA256 Key={KEY}, Timestamp={ts}, Cnonce={n}, Version=2, Signature={sig}",
       'Content-Type':'application/zip','X-FILENAME':'vcs-one-77.0.0.zip','Accept':'application/json'}
    r=urllib.request.Request(url,data=zip_bytes,headers=h,method='POST')
    try:
        with urllib.request.urlopen(r) as resp: return resp.status
    except urllib.error.HTTPError as e: return e.code
print(f"SCOPE | CONTROL in-scope artifact upload                  HTTP {upload()}")

tests=[('GET','/api/packages/',None),
       ('GET','/api/customers/',None),
       ('GET','/api/teams/',None),
       ('GET','/api/tokens/',None),
       ('GET','/api/organization/ssh-access-key',None),
       ('GET','/api/credentials/',None),
       ('POST','/api/tokens/','{"description":"oidc-escalation-probe","access":"read","accessToAllPackages":true,"expiresAt":"2026-11-20T00:00:00+00:00"}'),
       ('DELETE','/api/teams/99999999/',None)]
for m,p,b in tests:
    st,body=call(m,p,b)
    print(f"SCOPE | {m:6s} {p:42s} HTTP {st}  scope_blocked={'insufficient API scopes' in body}")
