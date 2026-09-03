"""P3-05 C42 two-stage runner; Train/Validation search then gated Test."""
import argparse,csv,json,hashlib,sys,warnings
from pathlib import Path
import numpy as np,pandas as pd,scipy.sparse as sp,sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import *
R=Path(__file__).resolve().parents[1]; B=R/'data/interim/phase2c/step23_phase3_execution_bundle'; O=R/'data/interim/phase3/p3_05_regime_c_seed42'; C=R/'data/interim/phase2c/step13_mixed_label_site_audit/combined_primary_dns_after_mixed_site_quarantine.jsonl'; F=R/'data/interim/phase3/p3_01_p3_02_integrity/engineered_features_full_corpus.csv'; A=R/'data/interim/phase2c/step19_private_psl_site_disjoint/regime_c_row_assignments_seed42.csv'; SH='34138ddc878dbbf33d585880624e0c6e022a362c2fcc66b3e121f89c75b504f5'; BH='60e505bf4e01879a2abfb42db2fc81ab763fec3265e0ae04525f0292b9061b40'
def h(p):
 d=hashlib.sha256(); d.update(p.read_bytes()); return d.hexdigest()
def jw(p,x): p.write_text(json.dumps(x,indent=2,sort_keys=True,default=int),encoding='utf8')
def lr(c): return LogisticRegression(C=c,solver='lbfgs',max_iter=1000,random_state=42,class_weight=None)
def pro(m,x): return m.predict_proba(x)[:,list(m.classes_).index(1)]
def met(y,p):
 z=(p>=.5).astype(int); tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel(); return {'MCC':matthews_corrcoef(y,z),'precision':precision_score(y,z,zero_division=0),'phishing_recall':recall_score(y,z),'specificity':tn/(tn+fp),'FPR':fp/(tn+fp),'balanced_accuracy':balanced_accuracy_score(y,z),'macro_f1':f1_score(y,z,average='macro'),'PR_AUC':average_precision_score(y,p),'ROC_AUC':roc_auc_score(y,p),'TN':int(tn),'FP':int(fp),'FN':int(fn),'TP':int(tp)},z
def ids(parts):
 out={x:[] for x in parts}
 with A.open(newline='',encoding='utf8') as q:
  for r in csv.DictReader(q):
   if r['partition'] in out: out[r['partition']].append(r['combined_row_id'])
 return out
def data(ii):
 s=set(ii); ff={}; uu={}
 with F.open(newline='',encoding='utf8') as q:
  for r in csv.DictReader(q):
   if r['combined_row_id'] in s: ff[r['combined_row_id']]=r
 with C.open(encoding='utf8') as q:
  for l in q:
   r=json.loads(l)
   if r['combined_row_id'] in s: uu[r['combined_row_id']]=r
 if set(ff)!=s or set(uu)!=s: raise RuntimeError('row join');
 ns=[x['name'] for x in json.loads((B/'engineered_feature_contract.json').read_text())['features']]
 x=np.array([[float(ff[i][n]) for n in ns] for i in ii]); y=np.array([int(ff[i]['label']) if ff[i]['label'].isdigit() else int(ff[i]['label']=='phishing') for i in ii]); u=[uu[i]['raw_url'] for i in ii]; return ns,x,y,u,ff,uu
def search():
 if sys.version.split()[0]!='3.10.11' or sklearn.__version__!='1.7.2' or h(A)!=SH or h(C)!='b850a96bda433c4d7207ae97a139d18692781b5bb70d2b5a13ef7920c467972d': raise RuntimeError('pre-fit integrity failure')
 O.mkdir(parents=True,exist_ok=False); ii=ids(['train','val']); ns,xt,yt,ut,_,_=data(ii['train']); _,xv,yv,uv,_,_=data(ii['val']); audit={'test_materialization_count':0,'test_transform_count':0,'test_prediction_count':0,'test_metric_count':0}; rows=[]; di=[]
 jw(O/'p3_05_execution_scope.json',{'regime':'C','split_seed':42,'models':['M1','M2','M3'],'purpose':'primary unseen-registrable-site integrity execution'}); jw(O/'p3_05_pre_fit_integrity.json',{'bundle_id':BH,'bundle_match':True,'corpus_sha_match':True,'split_sha256':SH,'expected_counts':{'train':86931,'val':18665,'test':18558},'test_access_audit':audit}); jw(O/'p3_05_label_mapping.json',{'benign':0,'phishing':1,'verified':True}); jw(O/'p3_05_hyperparameter_policy.json',{'policy':'SPLIT_AND_SEED_SPECIFIC_VALIDATION_SELECTION','A42_fitted_object_reuse':False,'selection_metric':'Validation MCC only'})
 sc=StandardScaler().fit(xt); sx,sv=sc.transform(xt),sc.transform(xv); vec={}
 grids={'M1':[{'C':x} for x in [.01,.1,1.,10.]],'M2':[{'max_iter':a,'learning_rate':b,'max_leaf_nodes':c} for a in [100,200] for b in [.05,.1] for c in [31,63]],'M3':[{'C':a,'max_features':b} for b in [25000,50000] for a in [.1,1.,10.]]}
 for mid,g in grids.items():
  for k,pa in enumerate(g,1):
   with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter('always')
    if mid=='M1': m=lr(pa['C']).fit(sx,yt); xx=sv
    elif mid=='M2': m=HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,early_stopping=False).fit(xt,yt); xx=xv
    else:
     mf=pa['max_features']; vec.setdefault(mf,TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=mf).fit(ut)); v=vec[mf]; tr=v.transform(ut); xx=v.transform(uv); m=lr(pa['C']).fit(tr,yt)
   if w: raise RuntimeError('warning')
   mm,_=met(yv,pro(m,xx)); rows.append({'model_id':mid,'candidate_id':f'{mid}_{k}','parameter_json':json.dumps(pa,sort_keys=True),'train_n':len(yt),'validation_n':len(yv),**{f'validation_{x}':z for x,z in mm.items() if x not in ['TN','FP','FN','TP']},'fit_status':'PASS','convergence_status':'CONVERGED'}); di.append({'model_id':mid,'candidate_id':f'{mid}_{k}','estimator_class':type(m).__name__,'convergence_status':'CONVERGED'})
 pd.DataFrame(rows).to_csv(O/'p3_05_hyperparameter_search.csv',index=False); sel={}
 for mid in grids:
  q=[r for r in rows if r['model_id']==mid]; best=max(r['validation_MCC'] for r in q); w=[r for r in q if r['validation_MCC']==best]
  if len(w)!=1: raise RuntimeError('tie')
  sel[mid]=w[0]
 freeze={'bundle_id':BH,'regime':'C','seed':42,'split_sha256':SH,'training_policy':'C42 Train only','selection_policy':'split-and-seed-specific Validation MCC','threshold':.5,'all_candidate_count':18,'candidate_count_M1':4,'candidate_count_M2':8,'candidate_count_M3':6,'configuration_complete':True,'test_gate_authorized':True,'timestamp':'2026-08-27'}
 for m in sel: freeze[f'{m}_selected_parameters']=json.loads(sel[m]['parameter_json']); freeze[f'{m}_validation_MCC']=sel[m]['validation_MCC']
 jw(O/'p3_05_selection_freeze.json',freeze); jw(O/'p3_05_selected_hyperparameters.json',sel); pd.DataFrame(di).to_csv(O/'p3_05_fit_diagnostics.csv',index=False); jw(O/'p3_05_stage1_test_access_audit.json',audit)
def test():
 fr=json.loads((O/'p3_05_selection_freeze.json').read_text());
 if not(fr.get('configuration_complete') and fr.get('test_gate_authorized') and fr.get('all_candidate_count')==18): raise RuntimeError('gate')
 it=ids(['test']); tid=it['test']; ns,xe,ye,ue,fe,uex=data(tid); it=ids(['train']); _,xt,yt,ut,_,_=data(it['train']); audit={'test_materialization_count':1,'test_transform_count':0,'test_prediction_count':0,'test_metric_count':0}; res=[]; cm=[]; (O/'predictions').mkdir(exist_ok=True)
 for mid in ['M1','M2','M3']:
  pa=fr[f'{mid}_selected_parameters']
  if mid=='M1': s=StandardScaler().fit(xt); m=lr(pa['C']).fit(s.transform(xt),yt); xx=s.transform(xe)
  elif mid=='M2': m=HistGradientBoostingClassifier(**pa,random_state=42,class_weight=None,early_stopping=False).fit(xt,yt); xx=xe
  else: v=TfidfVectorizer(analyzer='char',ngram_range=(2,6),sublinear_tf=True,min_df=5,norm='l2',max_features=pa['max_features']); m=lr(pa['C']).fit(v.fit_transform(ut),yt); xx=v.transform(ue); jw(O/'p3_05_m3_tfidf_diagnostics.json',{'actual_train_vocabulary_size':len(v.vocabulary_),'sparse':sp.issparse(xx),'format':xx.getformat(),'fit_boundary':'C42 TRAIN ONLY'})
  audit['test_transform_count']+=1; p=pro(m,xx); audit['test_prediction_count']+=1; mm,z=met(ye,p); audit['test_metric_count']+=1; res.append({'model_id':mid,'regime':'C','split_seed':42,'partition':'test','selected_hyperparameters':json.dumps(pa,sort_keys=True),'n_rows':len(ye),'n_benign':int((ye==0).sum()),'n_phishing':int((ye==1).sum()),'threshold':.5,**mm,'fit_status':'PASS','convergence_status':'CONVERGED'}); cm.append({'model_id':mid,**{x:mm[x] for x in ['TN','FP','FN','TP']},'n_rows':len(ye)})
  pd.DataFrame({'combined_row_id':tid,'model_id':mid,'regime':'C','split_seed':42,'partition':'test','true_label_numeric':ye,'predicted_label_numeric':z,'phishing_probability':p,'decision_threshold':.5,'site_key_private':[uex[i]['site_key_private'] for i in tid]}).to_csv(O/'predictions'/f'{mid}_regime_c_seed42_test_predictions.csv',index=False)
 pd.DataFrame(res).to_csv(O/'p3_05_test_metrics.csv',index=False); pd.DataFrame(cm).to_csv(O/'p3_05_confusion_matrices.csv',index=False); jw(O/'p3_05_stage2_test_access_audit.json',audit)
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('stage',choices=('search','test')); globals()[p.parse_args().stage]()
