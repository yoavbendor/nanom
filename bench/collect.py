#!/usr/bin/env python3
"""Run the nanom benchmarks and emit github-action-benchmark JSON.

Runs the parse-only and bulk benchmarks on a fixture, parses their stdout, and
writes an array of {name, unit, value} (lower-is-better ns/pkt). The benches
self-iterate (parse) / self-replicate (bulk), so no giant fixture is needed.
CI runners are noisy: bench.yml guards with a wide regression threshold and
only comments — these numbers are directional, not precise.
"""
import json, re, subprocess, sys, os

BUILD = sys.argv[1] if len(sys.argv) > 1 else "build"
FIX   = sys.argv[2] if len(sys.argv) > 2 else \
        "examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng"

def run(exe, *args):
    return subprocess.run([os.path.join(BUILD, exe), FIX, *map(str, args)],
                          capture_output=True, text=True, check=True).stdout

out = []
pb = run("nm_parse_bench", 400)                       # parse-only, 400 iters
for m in re.finditer(r'(nanom-\w+)\s+packets=\d+\s+best=[\d.]+ ms\s+([\d.]+) ns/pkt', pb):
    out.append({"name": f"decode {m.group(1)}", "unit": "ns/pkt", "value": float(m.group(2))})
bb = run("nm_bulk_bench", 400, 40)                    # bulk, 400x replicate, 40 iters
for m in re.finditer(r'(bulk-\w+)\s+best=[\d.]+ ms\s+([\d.]+) ns/pkt', bb):
    out.append({"name": f"bulk {m.group(1)}", "unit": "ns/pkt", "value": float(m.group(2))})

if not out:
    sys.stderr.write("no benchmark lines parsed\n--parse--\n"+pb+"\n--bulk--\n"+bb); sys.exit(1)
os.makedirs("bench", exist_ok=True)
json.dump(out, open("bench/output.json", "w"), indent=2)
print(json.dumps(out, indent=2))
