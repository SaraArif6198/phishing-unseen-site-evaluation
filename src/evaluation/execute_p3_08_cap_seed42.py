"""P3-08 matched cap sensitivity adapter; delegates to the audited two-stage runner."""
import argparse,csv
from pathlib import Path
import execute_p3_06_regime_a as x

p=argparse.ArgumentParser();p.add_argument('stage',choices=['search','test']);p.add_argument('variant',choices=['cap10','cap5']);p.add_argument('regime',choices=['a42','c42']);a=p.parse_args()
variant_key='in_class_cap10' if a.variant=='cap10' else 'in_class_cap5'
base_ids=x.ids
def capped_ids(seed,parts):
    # The frozen assignment is only filtered by the pre-existing cap flag.
    out={q:[] for q in parts}
    with x.assignment(seed).open(newline='',encoding='utf8') as f:
        for r in csv.DictReader(f):
            if r['partition'] in out and r[variant_key]=='True':out[r['partition']].append(r['combined_row_id'])
    return out
x.ROOT=x.R/'data/interim/phase3/p3_08_cap_sensitivities'/a.variant/a.regime
x.REGIME=f'{a.variant.upper()}_{a.regime[0].upper()}'
x.ids=capped_ids
getattr(x,a.stage)(42)
