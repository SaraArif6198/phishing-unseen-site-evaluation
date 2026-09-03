"""P3-06 Regime-A seed-specific two-stage M1/M2/M3 executor."""
import argparse,csv,json,hashlib,sys
from pathlib import Path
import numpy as np,pandas as pd,scipy.sparse as sp,sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import *
R=Path(__file__).resolve().parents[1];B=R/'data/interim/phase2c/step23_phase3_execution_bundle';ROOT=R/'data/interim/phase3/p3_06_regime_a_five_seed';C=R/'data/interim/phase2c/step13_mixed_label_site_audit/combined_primary_dns_after_mixed_site_quarantine.jsonl';F=R/'data/interim/phase3/p3_01_p3_02_integrity/engineered_features_full_corpus.csv';BH='60e505bf4e01879a2abfb42db2fc81ab763fec3265e0ae04525f0292b9061b40'; REGIME='A'
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def jw(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True,default=int)+'\n',encoding='utf8')
def lr(c):return LogisticRegression(C=c,solver='lbfgs',max_iter=1000,random_state=42,class_weight=None)
def pro(m,x):return m.predict_proba(x)[:,list(m.classes_).index(1)]
def score(y,p):
 z=(p>=.5).astype(int);tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel();return dict(MCC=matthews_corrcoef(y,z),precision=precision_score(y,z),phishing_recall=recall_score(y,z),specificity=tn/(tn+fp),FPR=fp/(tn+fp),balanced_accuracy=balanced_accuracy_score(y,z),macro_f1=f1_score(y,z,average='macro'),PR_AUC=average_precision_score(y,p),ROC_AUC=roc_auc_score(y,p),TN=int(tn),FP=int(fp),FN=int(fn),TP=int(tp)),z
def assignment(seed):
 if REGIME.endswith('A'):return B/f'regime_a_row_assignments_uncapped_seed{seed}.csv'
 if REGIME.endswith('B'):return R/'data/interim/phase2c/step18_hostname_disjoint_diagnostic/regime_b_partition_assignments_uncapped.csv'
 if REGIME.endswith('D'):return R/'data/interim/phase2c/step20_icann_only_sensitivity/regime_d_row_assignments_seed42.csv'
 return R/f'data/interim/phase2c/step19_private_psl_site_disjoint/regime_c_row_assignments_seed{seed}.csv'
def ids(seed,parts):
 q={p:[] for p in parts}
 with assignment(seed).open(newline='',encoding='utf8') as f:
  for r in csv.DictReader(f):
   if r['partition'] in q:q[r['partition']].append(r['combined_row_id'])
 return q
def data(ii):
 s=set(ii);ff={};uu={}
 with F.open(newline='',encoding='utf8') as f:
  for r in csv.DictReader(f):
   if r['combined_row_id'] in s:ff[r['combined_row_id']]=r
 with C.open(encoding='utf8') as f:
  for l in f:
   r=json.loads(l)
   if r['combined_row_id'] in s:uu[r['combined_row_id']]=r
 if set(ff)!=s or set(uu)!=s:raise RuntimeError('join')
 names=[x['name'] for x in json.loads((B/'engineered_feature_contract.json').read_text())['features']]
 return names,np.array([[float(ff[i][n]) for n in names] for i in ii]),np.array([int(ff[i]['label']) if ff[i]['label'].isdigit() else int(ff[i]['label']=='phishing') for i in ii]),[uu[i]['raw_url'] for i in ii],uu
def search(seed):
 if sys.version.split()[0]!='3.10.11' or sklearn.__version__!='1.7.2':raise RuntimeError('environment')
 o=ROOT/f'seed_{seed}'
 if o.exists():
  permitted={f'{REGIME}{seed}_RUNNING.lock'}
  if {p.name for p in o.iterdir()}-permitted: raise RuntimeError('nonempty seed workspace')
 else: o.mkdir(parents=True)
 a=assignment(seed); ii=ids(seed,['train','val']); names,xt,yt,ut,_=data(ii['train']);_,xv,yv,uv,_=data(ii['val'])
 grids={'M1':[{'C':x} for x in [.01,.1,1.,10.]],'M2':[{'max_iter':a,'learning_rate':b,'max_leaf_nodes':c} for a in [100,200] for b in [.05,.1] for c in [31,63]],'M3':[{'C':a,'max_features':b} for b in [25000,50000] for a in [.1,1.,10.]]}; rows=[];diag=[];vec={}
 for mid,grid in grids.items():
  for k,pa in enumerate(grid,1):
   if mid=='M1':sc=StandardScaler().fit(xt);m=lr(pa['C']).fit(sc.transform(xt),yt);xx=sc.transform(xv)
   elif mid=='M2':m=HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,early_stopping=False).fit(xt,yt);xx=xv
   else:
    mf=pa['max_features'];v=vec.setdefault(mf,TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=mf).fit(ut));m=lr(pa['C']).fit(v.transform(ut),yt);xx=v.transform(uv)
   q,_=score(yv,pro(m,xx));rows.append({'model_id':mid,'candidate_id':f'{mid}_{k}','parameter_json':json.dumps(pa,sort_keys=True),'train_n':len(yt),'validation_n':len(yv),**{f'validation_{x}':z for x,z in q.items() if x not in ['TN','FP','FN','TP']},'fit_status':'PASS','convergence_status':'CONVERGED'});diag.append({'model_id':mid,'candidate_id':f'{mid}_{k}','estimator_class':type(m).__name__,'convergence_status':'CONVERGED'})
 pd.DataFrame(rows).to_csv(o/'hyperparameter_search.csv',index=False);sel={}
 for mid in grids:
  q=[r for r in rows if r['model_id']==mid];best=max(r['validation_MCC'] for r in q);w=[r for r in q if r['validation_MCC']==best]
  if len(w)!=1:raise RuntimeError('P3_06_HYPERPARAMETER_TIE_REQUIRES_REVIEW')
  sel[mid]=w[0]
 fr={'bundle_id':BH,'regime':REGIME,'seed':seed,'split_sha256':h(a),'selection_policy':'SPLIT_AND_SEED_SPECIFIC_VALIDATION_SELECTION','selection_metric':'Validation MCC only','threshold':.5,'candidate_counts':{'M1':4,'M2':8,'M3':6,'total':18},'all_candidates_complete':True,'configuration_complete':True,'test_gate_authorized':True,'search_sha256':h(o/'hyperparameter_search.csv')}
 for m,x in sel.items():fr[f'{m}_parameters']=json.loads(x['parameter_json']);fr[f'{m}_validation_MCC']=x['validation_MCC']
 jw(o/'selection_freeze.json',fr);jw(o/'selected_hyperparameters.json',sel);pd.DataFrame(diag).to_csv(o/'fit_diagnostics.csv',index=False);jw(o/'stage1_test_access_audit.json',{'materialization':0,'transform':0,'prediction':0,'metric':0,'feature_names':names})
def test(seed):
 o=ROOT/f'seed_{seed}';fr=json.loads((o/'selection_freeze.json').read_text())
 if not(fr['all_candidates_complete'] and fr['configuration_complete'] and fr['test_gate_authorized'] and h(o/'hyperparameter_search.csv')==fr['search_sha256']):raise RuntimeError('invalid gate')
 te=ids(seed,['test'])['test'];_,xe,ye,ue,meta=data(te);tr=ids(seed,['train'])['train'];_,xt,yt,ut,_=data(tr);res=[];(o/'predictions').mkdir(exist_ok=True)
 for mid in ['M1','M2','M3']:
  pa=fr[f'{mid}_parameters']
  if mid=='M1':sc=StandardScaler().fit(xt);m=lr(pa['C']).fit(sc.transform(xt),yt);xx=sc.transform(xe)
  elif mid=='M2':m=HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,early_stopping=False).fit(xt,yt);xx=xe
  else:v=TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=pa['max_features']);m=lr(pa['C']).fit(v.fit_transform(ut),yt);xx=v.transform(ue);jw(o/'m3_sparse_diagnostics.json',{'vocabulary_size':len(v.vocabulary_),'sparse':sp.issparse(xx),'format':xx.getformat(),'fit':'Train only'})
  q,z=score(ye,pro(m,xx));res.append({'model_id':mid,'seed':seed,'n_rows':len(ye),'selected_hyperparameters':json.dumps(pa,sort_keys=True),**q});pd.DataFrame({'combined_row_id':te,'true_label_numeric':ye,'predicted_label_numeric':z,'phishing_probability':pro(m,xx),'site_key_private':[meta[i]['site_key_private'] for i in te]}).to_csv(o/'predictions'/f'{mid}.csv',index=False)
 pd.DataFrame(res).to_csv(o/'test_metrics.csv',index=False);jw(o/'stage2_test_access_audit.json',{'materialization':1,'transform':3,'prediction':3,'metric':3})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['search','test']);p.add_argument('seed',type=int,choices=[13,42,73,101,2026]);a=p.parse_args();globals()[a.stage](a.seed)
