"""Reproducible exploratory evaluation. Does not tune rules or assert accuracy."""
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from analyzer import analyze_text
from rules import RULESET_VERSION

def main():
    path=ROOT/"tests"/"evaluation.json"
    cases=json.loads(path.read_text(encoding="utf-8"))["cases"]
    totals={"tp":0,"fp":0,"tn":0,"fn":0,"abstained":0}
    results=[]
    for case in cases:
        result=analyze_text(case["content"])
        alert=result["risk"] in {"MEDIUM","HIGH"}
        bucket=("tp" if alert else "fn") if case["expected_alert"] else ("fp" if alert else "tn")
        totals[bucket]+=1
        totals["abstained"]+=result["status"]=="insufficient_evidence"
        results.append({"id":case["id"],"expected_alert":case["expected_alert"],"alert":alert,
                        "outcome":bucket,"risk":result["risk"],"score":result["score"],
                        "signals":[s["id"] for s in result["signals"]]})
    tp,fp,tn,fn=(totals[x] for x in ["tp","fp","tn","fn"])
    report={"ruleset":RULESET_VERSION,"dataset_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
            "dataset":"tests/evaluation.json","cases":len(cases),"alert_threshold":"MEDIUM or HIGH",
            "scope":"Synthetic, single-author exploratory evaluation; not real-world accuracy or an independent study. Abstentions count as negative predictions for this threshold.",
            "counts":totals,"precision":round(tp/(tp+fp),4) if tp+fp else None,
            "recall":round(tp/(tp+fn),4) if tp+fn else None,
            "false_positive_rate":round(fp/(fp+tn),4) if fp+tn else None,
            "results":results}
    out=ROOT/"docs"/"evaluation-results.json"
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:v for k,v in report.items() if k!="results"},ensure_ascii=False,indent=2))
    print("Errors:",", ".join(r["id"]+":"+r["outcome"] for r in results if r["outcome"] in {"fp","fn"}))

if __name__=="__main__":
    main()
