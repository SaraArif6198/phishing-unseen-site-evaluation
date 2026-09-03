"""P3-09 B42/D42 adapter for the audited two-stage M1/M2/M3 runner."""
import argparse
import execute_p3_06_regime_a as x
p=argparse.ArgumentParser();p.add_argument('stage',choices=['search','test']);p.add_argument('regime',choices=['b42','d42']);a=p.parse_args()
x.ROOT=x.R/'data/interim/phase3/p3_09_regime_b_d_diagnostics'/f'regime_{a.regime[0]}_seed42'
x.REGIME=a.regime[0].upper()
getattr(x,a.stage)(42)
