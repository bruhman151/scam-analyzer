"""Synthetic provider -> local HTTP analyzer. No real banking integration."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url",default="http://127.0.0.1:5000")
    parser.add_argument("--stress",type=int,default=0,help="Additional bounded concurrent text requests (max 1000)")
    args=parser.parse_args()
    if urlsplit(args.base_url).hostname not in {"localhost","127.0.0.1","::1"}:
        parser.error("Use a loopback service for the simulator")
    base=args.base_url.rstrip("/")
    def post(payload):
        req=urllib.request.Request(base+"/analyze",json.dumps(payload).encode(),
                                   headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req,timeout=20) as response:
            return json.load(response)
    cases=json.loads((ROOT/"tests"/"cases.json").read_text(encoding="utf-8"))
    records=[]
    for case in cases:
        start=time.perf_counter()
        result=post({"kind":case["kind"],"content":case["content"]})
        assert result["risk"]==case["expected_risk"],case["id"]
        records.append({"id":case["id"],"risk":result["risk"],"milliseconds":round((time.perf_counter()-start)*1000,2)})
    with urllib.request.urlopen(base+"/health",timeout=15) as response:
        health=json.load(response)
    if health["ocr"]["available"]:
        boundary=uuid.uuid4().hex
        image=(ROOT/"tests"/"fixtures"/"thai.png").read_bytes()
        body=(f"--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"thai.png\"\r\nContent-Type: image/png\r\n\r\n".encode()
              +image+f"\r\n--{boundary}--\r\n".encode())
        req=urllib.request.Request(base+"/analyze/image",body,headers={"Content-Type":f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req,timeout=20) as response:
            result=json.load(response)
        assert result["risk"]=="HIGH"
        records.append({"id":"IMAGE-THAI","risk":result["risk"]})
    count=min(max(args.stress,0),1000)
    if count:
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses=list(pool.map(lambda _:post({"kind":"text","content":"Share your OTP"}),range(count)))
        assert all(r["risk"]=="HIGH" for r in responses)
    report={"service_version":health["version"],"integration_cases":records,
            "concurrent_text_requests":count,"concurrent_failures":0,
            "ocr_exercised":health["ocr"]["available"]}
    (ROOT/"docs"/"integration-results.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(f"PASS: {len(records)} integration cases; {count} concurrent requests; OCR={health['ocr']['available']}")

if __name__=="__main__":
    main()
