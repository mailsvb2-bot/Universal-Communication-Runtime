#!/usr/bin/env python3
import argparse, base64, json, os, time, urllib.parse, urllib.request, uuid

def b64(v): return base64.b64encode(v.encode()).decode()

def validate_base_url(value):
    url=urllib.parse.urlsplit(value.rstrip("/"))
    loopback=url.hostname in {"127.0.0.1","localhost","::1"}
    if url.scheme!="https" and not (url.scheme=="http" and loopback):
        raise ValueError("UCR_BASE_URL must use HTTPS outside loopback development")
    return value.rstrip("/")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise urllib.error.HTTPError(args[0].full_url, args[2], "redirect blocked for authenticated UCR request", args[3], args[4])

def config():
    names=["UCR_BASE_URL","UCR_ACCESS_TOKEN","UCR_TENANT_ID","UCR_INTEGRATION_ID"]
    missing=[n for n in names if not os.environ.get(n)]
    if missing: raise SystemExit("missing environment: "+", ".join(missing))
    cfg={n:os.environ[n] for n in names}; cfg["UCR_BASE_URL"]=validate_base_url(cfg["UCR_BASE_URL"]); return cfg

def post(cfg,path,body,opener=None):
    req=urllib.request.Request(cfg["UCR_BASE_URL"]+path,data=json.dumps(body).encode(),headers={"authorization":"Bearer "+cfg["UCR_ACCESS_TOKEN"],"content-type":"application/json"},method="POST")
    with (opener or urllib.request.build_opener(NoRedirect)).open(req,timeout=15) as resp: return json.load(resp)

def flow_payloads(cfg, now_ms=None, run_id=None):
    now_ms=now_ms or int(time.time()*1000); run_id=run_id or uuid.uuid4().hex
    scope={"tenant_id":cfg["UCR_TENANT_ID"]}; integration_id=cfg["UCR_INTEGRATION_ID"]; prefix="reference-"+run_id
    create={"scope":scope,"integration_id":integration_id,"external_conference_id_b64":b64(prefix),"idempotency_key":prefix+"-create","mode":"webinar","schedule":{"starts_at_unix_ms":now_ms+300000,"planned_end_unix_ms":now_ms+3900000,"join_before_seconds":900,"join_after_seconds":300,"timezone":"UTC"}}
    return scope,integration_id,prefix,create

def execute_flow(cfg, transport=post, now_ms=None, run_id=None):
    scope,i,prefix,create=flow_payloads(cfg,now_ms,run_id); c=transport(cfg,"/v1/conferences",create)["conference"]; cid=c["conference_id"]
    for user,role in [("owner","owner"),("attendee","attendee")]:
        transport(cfg,"/v1/participants",{"scope":scope,"conference_id":cid,"integration_id":i,"external_user_id_b64":b64(prefix+"-"+user),"role":role,"idempotency_key":prefix+"-"+user})
        transport(cfg,"/v1/participant-devices",{"scope":scope,"conference_id":cid,"integration_id":i,"external_user_id_b64":b64(prefix+"-"+user),"idempotency_key":prefix+"-"+user+"-device"})
    transport(cfg,"/v1/conferences/runtime",{"scope":scope,"conference_id":cid,"integration_id":i,"idempotency_key":prefix+"-runtime"})
    for target in ("waiting","live"): transport(cfg,"/v1/conferences/lifecycle",{"scope":scope,"conference_id":cid,"integration_id":i,"target":target,"idempotency_key":prefix+"-"+target})
    grant=transport(cfg,"/v1/join-grants",{"scope":scope,"conference_id":cid,"integration_id":i,"external_user_id_b64":b64(prefix+"-attendee"),"ttl_seconds":900,"use_policy":"single_use","idempotency_key":prefix+"-join"})["grant"]
    return {"conference_id":cid,"join_url":grant["join_url"]}

def run(): print(json.dumps(execute_flow(config())))

def self_test():
    cfg={"UCR_BASE_URL":"https://ucr.example","UCR_ACCESS_TOKEN":"token","UCR_TENANT_ID":"tenant","UCR_INTEGRATION_ID":"integration"}
    calls=[]
    def fake(cfg,path,body,opener=None):
        calls.append((path,body))
        if path=="/v1/conferences": return {"conference":{"conference_id":"conference-1"}}
        if path=="/v1/join-grants": return {"grant":{"join_url":"https://join.example/#ucr_join=opaque"}}
        return {"ok":True}
    result=execute_flow(cfg,fake,1700000000000,"selftest")
    assert result["conference_id"]=="conference-1" and result["join_url"].endswith("#ucr_join=opaque")
    assert [p for p,_ in calls]==["/v1/conferences","/v1/participants","/v1/participant-devices","/v1/participants","/v1/participant-devices","/v1/conferences/runtime","/v1/conferences/lifecycle","/v1/conferences/lifecycle","/v1/join-grants"]
    try: validate_base_url("http://public.example"); raise AssertionError("plaintext public URL accepted")
    except ValueError: pass
    print("reference Python integration self-test: PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); a=p.parse_args(); self_test() if a.self_test else run()
