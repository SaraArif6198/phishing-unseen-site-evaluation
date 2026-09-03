"""P3-07 C-seed adapter using the validated two-stage implementation."""
import argparse
import execute_p3_06_regime_a as x
x.ROOT=x.R/'data/interim/phase3/p3_07_regime_c_multi_seed'; x.REGIME='C'
p=argparse.ArgumentParser();p.add_argument('stage',choices=['search','test']);p.add_argument('seed',type=int,choices=[123,456,789,1234]);a=p.parse_args();getattr(x,a.stage)(a.seed)
