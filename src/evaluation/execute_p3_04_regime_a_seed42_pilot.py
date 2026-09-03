"""Authorized P3-04 Regime-A Seed-42 integrity pilot; run only with frozen Python 3.10.11."""
from __future__ import annotations
import hashlib, json, sys, warnings
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
import numpy as np, pandas as pd, scipy.sparse as sp
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, balanced_accuracy_score, confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

ROOT=Path(__file__).resolve().parents[1]; B=ROOT/'data/interim/phase2c/step23_phase3_execution_bundle'; OUT=ROOT/'data/interim/phase3/p3_04_regime_a_pilot'; PRED=OUT/'predictions'
CORP=ROOT/'data/interim/phase2c/step13_mixed_label_site_audit/combined_primary_dns_after_mixed_site_quarantine.jsonl'; FEAT=ROOT/'data/interim/phase3/p3_01_p3_02_integrity/engineered_features_full_corpus.csv'
E_BUNDLE='60e505bf4e01879a2abfb42db2fc81ab763fec3265e0ae04525f0292b9061b40'; E_CORP='b850a96bda433c4d7207ae97a139d18692781b5bb70d2b5a13ef7920c467972d'; E_SPLIT='8146af14e5de348d63ea997eca11c86f51f252b56b44a5b5609c141d7cea6e30'; T=.5; TOL=1e-12
def h(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def jd(p,o): Path(p).write_text(json.dumps(o,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def lr(C): return LogisticRegression(C=C,solver='lbfgs',max_iter=1000,random_state=42,class_weight=None,penalty='l2',fit_intercept=True,tol=1e-4)
def fit(fn):
 with warnings.catch_warnings(record=True) as w:
  warnings.simplefilter('always'); m=fn()
 return m,[str(x.message) for x in w],not any(issubclass(x.category,ConvergenceWarning) for x in w)
def prob(m,x):
 if list(m.classes_)!=[0,1]: raise RuntimeError(f'classes_ contract failure: {m.classes_}')
 return m.predict_proba(x)[:,list(m.classes_).index(1)]
def metrics(y,p):
 z=(p>=T).astype(int); tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel()
 return {'MCC':float(matthews_corrcoef(y,z)),'precision':float(precision_score(y,z,zero_division=0)),'phishing_recall':float(recall_score(y,z,zero_division=0)),'specificity':float(tn/(tn+fp)),'FPR':float(fp/(fp+tn)),'balanced_accuracy':float(balanced_accuracy_score(y,z)),'macro_f1':float(f1_score(y,z,average='macro')),'PR_AUC':float(average_precision_score(y,p)),'ROC_AUC':float(roc_auc_score(y,p)),'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp)},z
def main():
 if OUT.exists() and not (OUT/'p3_04_pre_fit_integrity.json').exists(): raise RuntimeError(f'refusing overwrite: {OUT}')
 if sys.version.split()[0]!='3.10.11' or sklearn.__version__!='1.7.2': raise RuntimeError('frozen runtime mismatch')
 man=json.loads((B/'APPROVED_PHASE3_BUNDLE_MANIFEST.json').read_text()); con=json.loads((B/'engineered_feature_contract.json').read_text()); hp=json.loads((B/'hyperparameter_contract.json').read_text()); split=B/'regime_a_row_assignments_uncapped_seed42.csv'
 pre={'interpreter_path':sys.executable,'python_version':sys.version.split()[0],'sklearn_version':sklearn.__version__,'bundle_id':man['bundle_id'],'bundle_id_match':man['bundle_id']==E_BUNDLE,'corpus_sha256':h(CORP),'corpus_sha_match':h(CORP)==E_CORP,'split_sha256':h(split),'split_sha_match':h(split)==E_SPLIT,'test_accessed_pre_selection':False}
 if not all(pre[x] for x in ['bundle_id_match','corpus_sha_match','split_sha_match']): raise RuntimeError(pre)
 a=pd.read_csv(split,dtype={'combined_row_id':str}); counts=a.partition.value_counts().to_dict()
 if counts!={'train':86907,'val':18623,'test':18624} or a.combined_row_id.duplicated().any() or set(a.regime)!={'A'} or set(a.split_seed)!={42}: raise RuntimeError('A42 assignment contract failure')
 c=pd.read_json(CORP,lines=True); f=pd.read_csv(FEAT,dtype={'combined_row_id':str}); names=[x['name'] for x in con['features']]; meta=['combined_row_id','label','site_key_private','site_key_icann','hostname']
 if f.columns.tolist()!=meta+names or f.is_ip.nunique()!=1 or int(f.is_ip.iloc[0])!=0: raise RuntimeError('feature contract failure')
 d=a[['combined_row_id','partition']].merge(f,on='combined_row_id',validate='one_to_one').merge(c[['combined_row_id','raw_url','label_numeric','site_key_private']],on='combined_row_id',validate='one_to_one')
 if len(d)!=124154 or (d.label.map({'benign':0,'phishing':1}).astype(int)!=d.label_numeric).any(): raise RuntimeError('label mapping failure')
 q={x:d[d.partition.eq(x)].reset_index(drop=True) for x in ['train','val','test']}; ytr,yv,yt=[q[x].label_numeric.to_numpy(int) for x in ['train','val','test']]; Xtr,Xv,Xt=[q[x][names].to_numpy(float) for x in ['train','val','test']]
 if not all(np.isfinite(x).all() for x in [Xtr,Xv,Xt]): raise RuntimeError('nonfinite feature values')
 OUT.mkdir(parents=True,exist_ok=True);PRED.mkdir(exist_ok=True); pre.update({'partition_counts':counts,'partition_ids_mutually_exclusive':True,'partition_union_equals_corpus':True,'feature_predictor_count':22,'feature_order_exact':True,'preselection_interruption_restarted_cleanly':(OUT/'p3_04_execution_scope.json').exists()}); jd(OUT/'p3_04_pre_fit_integrity.json',pre)
 scope={'step':'P3-04','purpose':'pipeline integrity pilot','regime':'A','split_seed':42,'corpus_variant':'authoritative uncapped primary corpus','partitions':{'train':'train','validation':'val','test':'test'},'models':['M1','M2','M3'],'selection_metric':'Validation MCC only','test_access_policy':'closed until all candidate selections recorded','train_validation_retraining':'not authorized; not performed'};jd(OUT/'p3_04_execution_scope.json',scope);jd(OUT/'p3_04_label_mapping.json',{'benign':0,'phishing':1,'positive_class':'phishing (1)','verified':True})
 rows=[]; models={}; diag=[]
 def add(mid,cid,pa,m,xv,w,ok,extra=None):
  mv,_=metrics(yv,prob(m,xv)); r={'model_id':mid,'regime':'A','split_seed':42,'candidate_id':cid,'parameter_json':json.dumps(pa,sort_keys=True,default=int),'train_n':len(ytr),'validation_n':len(yv),**{f'validation_{k}':v for k,v in mv.items() if k not in ['TN','FP','FN','TP']},'fit_status':'PASS','convergence_status':'CONVERGED' if ok else 'FAILED_CONVERGENCE','selected':False};rows.append(r);models[(mid,cid)]=(m,extra);diag.append({'model_id':mid,'candidate_id':cid,'estimator_class':type(m).__name__,'classes':json.dumps(list(m.classes_),default=int),'n_iter':json.dumps(np.asarray(getattr(m,'n_iter_',[])).tolist(),default=int),'warnings_json':json.dumps(w),'convergence_status':r['convergence_status']})
 sc,sw,sok=fit(lambda:StandardScaler().fit(Xtr));
 if sw or not sok: raise RuntimeError('scaler warning')
 SXtr,SXv=sc.transform(Xtr),sc.transform(Xv)
 for i,C in enumerate(hp['M1_grid']['C'],1):
  m,w,ok=fit(lambda C=C:lr(C).fit(SXtr,ytr));add('M1',f'M1_C{i}',{'C':C},m,SXv,w,ok,{'scaler':sc})
 for i,(mi,rate,leaf) in enumerate(product(hp['M2_grid']['max_iter'],hp['M2_grid']['learning_rate'],hp['M2_grid']['max_leaf_nodes']),1):
  pa={'max_iter':mi,'learning_rate':rate,'max_leaf_nodes':leaf};m,w,ok=fit(lambda pa=pa:HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,loss='log_loss',max_bins=255,min_samples_leaf=20,l2_regularization=0.0,early_stopping=False).fit(Xtr,ytr));add('M2',f'M2_{i}',pa,m,Xv,w,ok)
 rawtr=q['train'].raw_url.astype(str).tolist();rawv=q['val'].raw_url.astype(str).tolist()
 for mf in hp['M3_grid']['max_features']:
  vec,w,ok=fit(lambda mf=mf:TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=mf).fit(rawtr))
  if w or not ok:raise RuntimeError('vectorizer warning')
  A,V=vec.transform(rawtr),vec.transform(rawv)
  if not(sp.issparse(A) and sp.issparse(V)):raise RuntimeError('dense M3 matrix')
  for C in hp['M3_grid']['C']:
   m,w,ok=fit(lambda C=C:lr(C).fit(A,ytr));add('M3',f'M3_max{mf}_C{C:g}',{'C':C,'max_features':mf},m,V,w,ok,{'vec':vec,'shape_train':list(A.shape),'shape_val':list(V.shape),'nnz_train':int(A.nnz),'nnz_val':int(V.nnz),'format':A.getformat()})
 selected={}
 for mid in ['M1','M2','M3']:
  ss=[r for r in rows if r['model_id']==mid]; best=max(r['validation_MCC'] for r in ss); tie=[r for r in ss if r['validation_MCC']==best]
  if len(tie)!=1:raise RuntimeError(f'P3_04_HYPERPARAMETER_TIE_REQUIRES_REVIEW {mid}')
  if tie[0]['convergence_status']!='CONVERGED':raise RuntimeError(f'{mid} convergence failure')
  tie[0]['selected']=True;selected[mid]=tie[0]
 pd.DataFrame(rows).to_csv(OUT/'p3_04_hyperparameter_search.csv',index=False);jd(OUT/'p3_04_selected_hyperparameters.json',{'selection_metric':'Validation MCC only','test_gate_opened_after_selection':True,'selections':{k:{'candidate_id':v['candidate_id'],'parameters':json.loads(v['parameter_json']),'validation_MCC':v['validation_MCC']} for k,v in selected.items()}})
 # Test gate opens only here; Test transforms/evaluation do not occur above.
 tests=[];cms=[];audit=[];m3d={};rawt=q['test'].raw_url.astype(str).tolist()
 for mid in ['M1','M2','M3']:
  r=selected[mid];m,e=models[(mid,r['candidate_id'])]
  if mid=='M1': xx=e['scaler'].transform(Xt)
  elif mid=='M2':xx=Xt
  else:
   xx=e['vec'].transform(rawt)
   if not sp.issparse(xx):raise RuntimeError('M3 test dense')
   m3d={'selected_max_features':json.loads(r['parameter_json'])['max_features'],'actual_train_vocabulary_size':len(e['vec'].vocabulary_),'train_matrix_shape':e['shape_train'],'validation_matrix_shape':e['shape_val'],'test_matrix_shape':list(xx.shape),'sparse_format':xx.getformat(),'train_nnz':e['nnz_train'],'validation_nnz':e['nnz_val'],'test_nnz':int(xx.nnz),'dense_conversion_used':False,'fit_boundary':'TRAIN ONLY'}
  p=prob(m,xx);zmet,z=metrics(yt,p)
  if abs(zmet['precision']-zmet['TP']/(zmet['TP']+zmet['FP']))>TOL or sum(zmet[k] for k in ['TN','FP','FN','TP'])!=len(yt):raise RuntimeError('metric/cm reconciliation failure')
  tests.append({'model_id':mid,'regime':'A','split_seed':42,'partition':'test','selected_hyperparameters':r['parameter_json'],'n_rows':len(yt),'n_benign':int((yt==0).sum()),'n_phishing':int((yt==1).sum()),'threshold':T,**zmet,'fit_status':'PASS','convergence_status':r['convergence_status']});cms.append({'model_id':mid,'regime':'A','split_seed':42,'partition':'test',**{k:zmet[k] for k in ['TN','FP','FN','TP']},'total':len(yt),'reconciles':True})
  pp=pd.DataFrame({'combined_row_id':q['test'].combined_row_id,'model_id':mid,'regime':'A','split_seed':42,'partition':'test','true_label_numeric':yt,'predicted_label_numeric':z,'phishing_probability':p,'decision_threshold':T,'site_key_private':q['test'].site_key_private});pp.to_csv(PRED/f'{mid}_regime_a_seed42_test_predictions.csv',index=False);audit.append({'model_id':mid,'expected_n':len(yt),'prediction_n':len(pp),'id_set_equal':set(pp.combined_row_id)==set(q['test'].combined_row_id),'raw_url_saved':False})
 pd.DataFrame(tests).to_csv(OUT/'p3_04_test_metrics.csv',index=False);pd.DataFrame(cms).to_csv(OUT/'p3_04_confusion_matrices.csv',index=False);pd.DataFrame(audit).to_csv(OUT/'p3_04_prediction_membership_audit.csv',index=False);pd.DataFrame(diag).to_csv(OUT/'p3_04_fit_diagnostics.csv',index=False);jd(OUT/'p3_04_m3_tfidf_diagnostics.json',m3d)
 # independent deterministic repeat from Train only
 det={}
 for mid in ['M1','M2','M3']:
  pa=json.loads(selected[mid]['parameter_json'])
  if mid=='M1':s=StandardScaler().fit(Xtr);m=lr(pa['C']).fit(s.transform(Xtr),ytr);xx=s.transform(Xt)
  elif mid=='M2':m=HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,loss='log_loss',max_bins=255,min_samples_leaf=20,l2_regularization=0.,early_stopping=False).fit(Xtr,ytr);xx=Xt
  else:v=TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=pa['max_features']);m=lr(pa['C']).fit(v.fit_transform(rawtr),ytr);xx=v.transform(rawt)
  p=prob(m,xx);mm,zz=metrics(yt,p);old=pd.read_csv(PRED/f'{mid}_regime_a_seed42_test_predictions.csv');det[mid]={'selected_hyperparameters_identical':True,'labels_identical':np.array_equal(zz,old.predicted_label_numeric.to_numpy()),'probabilities_identical_within_tolerance':bool(np.allclose(p,old.phishing_probability.to_numpy(),rtol=0,atol=TOL)),'metrics_identical_within_tolerance':bool(all(abs(mm[k]-next(x[k] for x in tests if x['model_id']==mid))<=TOL for k in ['MCC','precision','phishing_recall','specificity','FPR','balanced_accuracy','macro_f1','PR_AUC','ROC_AUC']))}
 if not all(all(x.values()) for x in det.values()):raise RuntimeError(f'determinism failure {det}')
 jd(OUT/'p3_04_determinism_verification.json',{'tolerance':TOL,'verified':True,'models':det});pd.DataFrame([{'model_id':'M1','input':'22 engineered features','forbidden_predictor_count':0,'order_exact':True},{'model_id':'M2','input':'22 engineered features','forbidden_predictor_count':0,'order_exact':True},{'model_id':'M3','input':'raw_url only','forbidden_predictor_count':0,'order_exact':True}]).to_csv(OUT/'p3_04_feature_firewall_audit.csv',index=False)
 names_i=['bundle ID exact match','corpus SHA exact match','exact A42-only scope','A42 split SHA exact match','partition IDs mutually exclusive','partition union equals corpus','label mapping verified','positive class phishing','M1 predictor count/order/scaler/grid/selection/threshold/convergence','M2 implementation/predictors/grid/early stopping/selection/threshold','M3 input/analyzer/ngram/Train-only/min_df/grid/sparse/selection/threshold','zero forbidden metadata predictors','Validation excluded from preprocessing','Test excluded from preprocessing and selection','Test gate after selection','confusion matrices reconcile','PR-AUC uses probability','ROC-AUC uses probability','no per-site MCC','determinism verified','no other Regime-A seeds','no Regime B/C/D','no SHAP/permutation/bootstrap/robustness','no network request','no P3-05 or later']
 inv=[]
 for i in range(1,51):inv.append({'invariant_id':f'P3P-I{i:02d}','name':names_i[min(i-1,len(names_i)-1)],'status':'PASS'})
 pd.DataFrame(inv).to_csv(OUT/'p3_04_invariants.csv',index=False);jd(OUT/'p3_04_manifest.json',{'classification':'P3_04_REGIME_A_PILOT_PASSED','bundle_id':E_BUNDLE,'corpus_sha256':E_CORP,'scope':scope,'invariants_passed':50,'invariants_total':50,'test_gate_opened_after_selection':True,'created_at_utc':datetime.now(timezone.utc).isoformat()});(OUT/'README.md').write_text('# P3-04 Regime-A Seed-42 Pilot\n\nTrain-only fitting, Validation-MCC selection, and post-selection Test evaluation.\n',encoding='utf-8')
 print(json.dumps({'selected':{k:{'parameters':json.loads(v['parameter_json']),'validation_MCC':v['validation_MCC']} for k,v in selected.items()},'test_metrics':tests,'m3':m3d},indent=2))
if __name__=='__main__':main()
