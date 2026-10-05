"""Compare identical policies, then measure latency and traced Python memory."""
import json
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import tracemalloc
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from analyzer import analyze_text, analyze_text_reference
from rules import RULESET_VERSION

def percentile(values, q):
    return sorted(values)[min(len(values)-1,int(len(values)*q))]

def main():
    base=json.loads((ROOT/"tests"/"cases.json").read_text(encoding="utf-8"))
    normal=[c["content"] for c in base if c["kind"]=="text"]
    evaluation=json.loads((ROOT/"tests"/"evaluation.json").read_text(encoding="utf-8"))["cases"]
    texts=normal+[c["content"] for c in evaluation]
    rng=random.Random(27)
    pieces=normal+["ก"*200,"😀"*50,"\u200bOTP", "https://example.org/"]
    texts += ["\n".join(rng.choices(pieces,k=rng.randint(1,25)))[:5000] for _ in range(1000)]
    texts += ["a"*5000,"ส่ง"*1666, "โอนเงิน. "*500, "Send OTP. "*500]
    for i,text in enumerate(texts):
        if analyze_text(text)!=analyze_text_reference(text):
            raise AssertionError(f"Output mismatch at index {i}")
    workloads={"short_messages":normal,"long_repeated":texts[-4:]}
    timings={}
    for name,inputs in workloads.items():
        numbers={"reference":[],"optimized":[]}
        for round_ in range(7):
            order=[("reference",analyze_text_reference),("optimized",analyze_text)]
            if round_%2: order.reverse()
            for label,fn in order:
                for text in inputs*15:
                    start=time.perf_counter_ns()
                    fn(text)
                    numbers[label].append((time.perf_counter_ns()-start)/1e6)
        timings[name]={label:{"median_ms":round(statistics.median(values),4),
                             "p95_ms":round(percentile(values,.95),4),
                             "mean_ms":round(statistics.mean(values),4)}
                       for label,values in numbers.items()}
    tracemalloc.start()
    for text in texts:
        analyze_text(text)
    _,peak=tracemalloc.get_traced_memory()
    tracemalloc.stop()
    report={"ruleset":RULESET_VERSION,"python":platform.python_version(),"platform":platform.system(),
            "output_equivalence_cases":len(texts),"mismatches":0,"timings":timings,
            "peak_traced_python_bytes":peak,
            "limits":"Microbenchmark in this environment, not a production SLA. Excludes HTTP/OCR and native process memory; synthetic workload. Reference uses the same policy without per-rule early exit."}
    (ROOT/"docs"/"benchmark-results.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))

if __name__=="__main__":
    main()
